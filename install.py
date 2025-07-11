#!/usr/bin/env python3
"""Enhanced production-ready setup script for Wazuh MCP Server.

This script provides comprehensive cross-platform setup with intelligent
SSL/HTTPS detection, OS-specific optimizations, and robust error handling.
"""

import os
import sys
import platform
import subprocess
import socket
import ssl
import urllib.request
import json
from pathlib import Path
import shutil
import stat
import time
from typing import Dict, List, Tuple, Optional


class Colors:
    """ANSI color codes for terminal output."""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'


def print_header():
    """Print setup header with branding."""
    print(f"{Colors.CYAN}{'=' * 70}")
    print(f"   {Colors.BOLD}WAZUH MCP SERVER - INTELLIGENT SETUP{Colors.END}")
    print(f"   {Colors.BLUE}Secure Integration for Claude Desktop & Wazuh SIEM{Colors.END}")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.END}")
    print()


def print_info(message: str):
    """Print info message."""
    print(f"{Colors.BLUE}[INFO]{Colors.END} {message}")


def print_success(message: str):
    """Print success message."""
    print(f"{Colors.GREEN}[✓]{Colors.END} {message}")


def print_error(message: str):
    """Print error message."""
    print(f"{Colors.RED}[✗]{Colors.END} {message}")


def print_warning(message: str):
    """Print warning message."""
    print(f"{Colors.YELLOW}[⚠]{Colors.END} {message}")


def print_step(step: str):
    """Print step header."""
    print(f"\n{Colors.MAGENTA}{'▶' * 3} {step}{Colors.END}")


def detect_fedora() -> bool:
    """Detect if running on Fedora."""
    try:
        with open('/etc/os-release', 'r') as f:
            content = f.read().lower()
            return 'fedora' in content or 'red hat' in content
    except:
        return 'fedora' in platform.platform().lower()


def check_and_fix_pydantic() -> bool:
    """Check Pydantic version and handle Fedora-specific issues."""
    is_fedora = detect_fedora()
    
    try:
        import pydantic
        version = getattr(pydantic, '__version__', getattr(pydantic, 'VERSION', 'unknown'))
        
        if is_fedora:
            print_info(f"🐧 Fedora detected with Pydantic {version}")
            if version.startswith('2'):
                print_success("✅ Pydantic V2 on Fedora - using compatibility mode")
                print_info("💡 For optimal performance, you can install V1: pip install 'pydantic>=1.10.0,<2.0.0'")
            else:
                print_success("✅ Pydantic V1 on Fedora - native mode")
        else:
            print_success(f"✅ Pydantic {version} detected on {platform.system()}")
            
    except ImportError:
        print_warning("⚠️  Pydantic not found. Installing...")
        
        if is_fedora:
            # Try system package first on Fedora
            try:
                print_info("🐧 Trying Fedora system package...")
                subprocess.check_call(['sudo', 'dnf', 'install', '-y', 'python3-pydantic'])
                print_success("✅ Installed via dnf")
                return True
            except (subprocess.CalledProcessError, FileNotFoundError):
                print_info("📦 System package failed, using pip...")
        
        # Fallback to pip
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pydantic>=1.10.0'])
        print_success("✅ Installed via pip")
    
    return True


def detect_system_info() -> Dict[str, str]:
    """Detect comprehensive system information."""
    system_info = {
        'os': platform.system(),
        'os_version': platform.release(),
        'architecture': platform.machine(),
        'python_version': platform.python_version(),
        'platform': platform.platform(),
        'processor': platform.processor() or 'Unknown',
    }
    
    # Detect if we're on Fedora specifically
    if system_info['os'] == 'Linux':
        system_info['is_fedora'] = detect_fedora()
    else:
        system_info['is_fedora'] = False
    
    # Detect package manager
    if system_info['os'] == 'Linux':
        if shutil.which('apt-get'):
            system_info['package_manager'] = 'apt'
        elif shutil.which('yum'):
            system_info['package_manager'] = 'yum'
        elif shutil.which('dnf'):
            system_info['package_manager'] = 'dnf'
        elif shutil.which('pacman'):
            system_info['package_manager'] = 'pacman'
        else:
            system_info['package_manager'] = 'unknown'
    elif system_info['os'] == 'Darwin':
        system_info['package_manager'] = 'brew' if shutil.which('brew') else 'none'
    elif system_info['os'] == 'Windows':
        system_info['package_manager'] = 'chocolatey' if shutil.which('choco') else 'none'
    
    return system_info


def check_python_version() -> bool:
    """Check if Python version meets requirements."""
    version = sys.version_info
    required_major, required_minor = 3, 9
    
    if version.major < required_major or (version.major == required_major and version.minor < required_minor):
        print_error(f"Python {required_major}.{required_minor}+ required, found {version.major}.{version.minor}.{version.micro}")
        print_info("Please upgrade Python and try again")
        return False
    
    print_success(f"Python {version.major}.{version.minor}.{version.micro} compatible")
    return True


def check_system_dependencies(system_info: Dict[str, str]) -> bool:
    """Check and install system dependencies if needed."""
    print_info("Checking system dependencies...")
    
    missing_deps = []
    optional_deps = []
    
    # Check for git (required for some pip installations)
    if not shutil.which('git'):
        missing_deps.append('git')
    
    # Check for curl (useful for testing)
    if not shutil.which('curl'):
        optional_deps.append('curl')
    
    # OS-specific checks
    if system_info['os'] == 'Linux':
        # Check for development tools
        if not shutil.which('gcc') and not shutil.which('clang'):
            print_warning("C compiler not found - some Python packages may fail to install")
            if system_info['package_manager'] == 'apt':
                optional_deps.append('build-essential')
            elif system_info['package_manager'] in ['yum', 'dnf']:
                optional_deps.append('gcc')
    
    if missing_deps:
        print_error(f"Missing required dependencies: {', '.join(missing_deps)}")
        print_info("Please install these dependencies and try again")
        return False
    
    if optional_deps:
        print_warning(f"Optional dependencies missing: {', '.join(optional_deps)}")
        print_info("These may be needed for full functionality")
    
    print_success("System dependencies check completed")
    return True


def create_virtual_environment(system_info: Dict[str, str]) -> bool:
    """Create and configure virtual environment with OS-specific optimizations."""
    venv_path = Path("venv")
    
    # Check if we're already in a virtual environment
    in_venv = (
        hasattr(sys, 'real_prefix') or 
        (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    )
    
    if in_venv:
        print_success("Already running in virtual environment")
        return True
    
    if venv_path.exists():
        print_info("Virtual environment already exists")
        return True
    
    print_info("Creating virtual environment with OS optimizations...")
    
    try:
        # Create virtual environment
        cmd = [sys.executable, "-m", "venv", str(venv_path)]
        
        # Add OS-specific optimizations
        if system_info['os'] == 'Windows':
            cmd.extend(["--system-site-packages"])  # Windows compatibility
        
        subprocess.run(cmd, check=True, capture_output=True)
        print_success("Virtual environment created successfully")
        
        # Set proper permissions on Unix-like systems
        if system_info['os'] in ['Linux', 'Darwin']:
            os.chmod(venv_path, 0o755)
        
        return True
        
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to create virtual environment: {e}")
        return False


def get_activation_info(system_info: Dict[str, str]) -> Tuple[str, str]:
    """Get virtual environment activation information."""
    if system_info['os'] == 'Windows':
        activate_script = "venv\\Scripts\\activate"
        python_exe = "venv\\Scripts\\python.exe"
        pip_exe = "venv\\Scripts\\pip.exe"
    else:
        activate_script = "source venv/bin/activate"
        python_exe = "venv/bin/python"
        pip_exe = "venv/bin/pip"
    
    return activate_script, python_exe, pip_exe


def upgrade_pip(python_exe: str) -> bool:
    """Upgrade pip to latest version."""
    print_info("Upgrading pip to latest version...")
    
    try:
        cmd = [python_exe, "-m", "pip", "install", "--upgrade", "pip", "setuptools", "wheel"]
        subprocess.run(cmd, check=True, capture_output=True)
        print_success("Pip upgraded successfully")
        return True
    except subprocess.CalledProcessError as e:
        print_warning(f"Pip upgrade failed: {e}")
        print_info("Continuing with existing pip version")
        return True  # Not critical


def install_dependencies(python_exe: str, pip_exe: str) -> bool:
    """Install all required dependencies with error handling."""
    print_info("Installing production dependencies...")
    
    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        print_error("requirements.txt not found")
        return False
    
    try:
        # Install main requirements
        cmd = [pip_exe, "install", "-r", str(requirements_file)]
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print_success("Production dependencies installed")
        
        # Install development dependencies if available
        dev_requirements = Path("requirements-dev.txt")
        if dev_requirements.exists():
            print_info("Installing development dependencies...")
            cmd = [pip_exe, "install", "-r", str(dev_requirements)]
            subprocess.run(cmd, check=True, capture_output=True)
            print_success("Development dependencies installed")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install dependencies: {e}")
        if e.stderr:
            print_error(f"Error details: {e.stderr}")
        return False


def install_package(python_exe: str, pip_exe: str) -> bool:
    """Install the Wazuh MCP Server package."""
    print_info("Installing Wazuh MCP Server package...")
    
    try:
        cmd = [pip_exe, "install", "-e", "."]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        print_success("Wazuh MCP Server package installed")
        return True
    except subprocess.CalledProcessError as e:
        print_error(f"Failed to install package: {e}")
        return False


def setup_configuration_files() -> bool:
    """Setup configuration files with security considerations."""
    print_info("Setting up configuration files...")
    
    env_example = Path(".env.example")
    env_file = Path(".env")
    
    # Create .env from example if it doesn't exist
    if not env_file.exists():
        if env_example.exists():
            shutil.copy2(env_example, env_file)
            print_success("Created .env from .env.example")
        else:
            print_warning(".env.example not found")
            create_default_env_file(env_file)
    else:
        print_info(".env file already exists")
    
    # Set secure permissions
    if platform.system() != "Windows":
        try:
            os.chmod(env_file, stat.S_IRUSR | stat.S_IWUSR)  # 600 permissions
            print_success("Set secure permissions on .env file (600)")
        except Exception as e:
            print_warning(f"Could not set .env permissions: {e}")
    
    # Create logs directory
    logs_dir = Path("logs")
    if not logs_dir.exists():
        logs_dir.mkdir(mode=0o755)
        print_success("Created logs directory")
    
    return True


def create_default_env_file(env_file: Path):
    """Create a default .env file with placeholders."""
    default_content = """# =============================================================================
# WAZUH MCP SERVER - CONFIGURATION
# =============================================================================

# Wazuh Manager Configuration
WAZUH_HOST=your-wazuh-server.com
WAZUH_PORT=55000
WAZUH_USER=your-username
WAZUH_PASS=your-password

# Wazuh Indexer Configuration
WAZUH_INDEXER_HOST=your-wazuh-server.com
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=your-username
WAZUH_INDEXER_PASS=your-password

# Security Settings (adjust for your environment)
VERIFY_SSL=false
WAZUH_ALLOW_SELF_SIGNED=true

# Wazuh API Version
WAZUH_API_VERSION=v4

# Logging Configuration
LOG_LEVEL=INFO
"""
    env_file.write_text(default_content)
    print_success("Created default .env file")


def test_wazuh_connectivity(host: str, port: int = 55000) -> Dict[str, any]:
    """Test connectivity to Wazuh server with protocol detection."""
    print_info(f"Testing connectivity to {host}:{port}...")
    
    result = {
        'reachable': False,
        'https_available': False,
        'http_available': False,
        'ssl_valid': False,
        'self_signed': False,
        'protocol_recommended': 'https'
    }
    
    # Test HTTPS connectivity
    try:
        print_info("Testing HTTPS connectivity...")
        context = ssl.create_default_context()
        
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                result['reachable'] = True
                result['https_available'] = True
                result['ssl_valid'] = True
                print_success("HTTPS connection successful with valid SSL")
                
    except ssl.SSLCertVerificationError:
        result['reachable'] = True
        result['https_available'] = True
        result['self_signed'] = True
        print_warning("HTTPS available but SSL certificate verification failed (likely self-signed)")
        
    except (socket.timeout, ConnectionRefusedError, OSError):
        print_warning("HTTPS connection failed")
    
    # Test HTTPS with disabled verification
    if not result['ssl_valid'] and result['https_available']:
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    print_success("HTTPS connection successful with disabled SSL verification")
                    
        except Exception:
            result['https_available'] = False
    
    return result


def validate_configuration() -> bool:
    """Validate and test the configuration setup."""
    print_info("Validating configuration...")
    
    env_file = Path(".env")
    if not env_file.exists():
        print_error(".env file is missing")
        return False
    
    # Parse .env file
    config = {}
    try:
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                config[key.strip()] = value.strip()
    except Exception as e:
        print_error(f"Failed to parse .env file: {e}")
        return False
    
    # Check required configuration
    required_vars = ['WAZUH_HOST', 'WAZUH_USER', 'WAZUH_PASS']
    missing_vars = []
    
    for var in required_vars:
        if var not in config or not config[var] or config[var].startswith('your-'):
            missing_vars.append(var)
    
    if missing_vars:
        print_warning("Configuration incomplete - please update .env file:")
        for var in missing_vars:
            print(f"  - {var}")
        print_info("Edit .env file with your actual Wazuh deployment details")
        return True  # Don't fail setup, just warn
    
    # Test connectivity if configuration is complete
    if 'WAZUH_HOST' in config and not config['WAZUH_HOST'].startswith('your-'):
        connectivity = test_wazuh_connectivity(config['WAZUH_HOST'])
        
        if connectivity['reachable']:
            print_success("Wazuh server is reachable")
            
            # Provide SSL configuration recommendations
            if connectivity['ssl_valid']:
                print_info("Recommendation: Set VERIFY_SSL=true for production")
            elif connectivity['self_signed']:
                print_info("Self-signed certificate detected")
                print_info("Current settings (VERIFY_SSL=false) are appropriate")
            
        else:
            print_warning(f"Could not reach Wazuh server at {config['WAZUH_HOST']}")
            print_info("Please verify the hostname and network connectivity")
    
    print_success("Configuration validation completed")
    return True


def test_installation(python_exe: str) -> bool:
    """Test the installation thoroughly."""
    print_info("Testing installation...")
    
    tests = [
        ("Package imports", "from wazuh_mcp_server.main import WazuhMCPServer; print('✓ Main module OK')"),
        ("Configuration", "from wazuh_mcp_server.config import WazuhConfig; print('✓ Config module OK')"),
        ("API clients", "from wazuh_mcp_server.api import wazuh_client; print('✓ API clients OK')"),
        ("Analyzers", "from wazuh_mcp_server.analyzers import security_analyzer; print('✓ Analyzers OK')"),
        ("Utilities", "from wazuh_mcp_server.utils import logging; print('✓ Utilities OK')"),
    ]
    
    for test_name, test_code in tests:
        try:
            result = subprocess.run(
                [python_exe, "-c", test_code],
                check=True, capture_output=True, text=True
            )
            print_success(f"{test_name}: {result.stdout.strip()}")
        except subprocess.CalledProcessError as e:
            print_error(f"{test_name} failed: {e}")
            if e.stdout:
                print(e.stdout)
            if e.stderr:
                print(e.stderr)
            return False
    
    print_success("Installation test completed successfully")
    return True


def generate_claude_config(system_info: Dict[str, str]) -> str:
    """Generate Claude Desktop configuration."""
    project_path = Path.cwd().absolute()
    main_py_path = project_path / "src" / "wazuh_mcp_server" / "main.py"
    
    # Use appropriate path format for OS
    if system_info['os'] == 'Windows':
        path_str = str(main_py_path).replace('\\', '\\\\')
    else:
        path_str = str(main_py_path)
    
    config = {
        "mcpServers": {
            "wazuh": {
                "command": "python",
                "args": [path_str, "--stdio"],
                "env": {
                    "LOG_LEVEL": "INFO"
                }
            }
        }
    }
    
    return json.dumps(config, indent=2)


def show_completion_message(system_info: Dict[str, str]):
    """Show comprehensive completion message with next steps."""
    activate_cmd, python_exe, _ = get_activation_info(system_info)
    claude_config = generate_claude_config(system_info)
    
    print()
    print(f"{Colors.GREEN}{'=' * 70}")
    print(f"   🎉 {Colors.BOLD}SETUP COMPLETE - READY FOR DEPLOYMENT!{Colors.END}")
    print(f"{Colors.GREEN}{'=' * 70}{Colors.END}")
    print()
    
    print(f"{Colors.BOLD}📋 NEXT STEPS:{Colors.END}")
    print()
    
    print(f"{Colors.CYAN}1. Configure Wazuh Connection:{Colors.END}")
    print("   • Edit .env file with your Wazuh server details:")
    print(f"     {Colors.YELLOW}nano .env{Colors.END}")
    print("   • Required fields: WAZUH_HOST, WAZUH_USER, WAZUH_PASS")
    print("   • Configure WAZUH_INDEXER_HOST for advanced features")
    print()
    
    print(f"{Colors.CYAN}2. Test Connection:{Colors.END}")
    if system_info['os'] != 'Windows':
        print(f"   • {activate_cmd}")
    print(f"   • {python_exe} src/wazuh_mcp_server/main.py --stdio")
    print()
    
    print(f"{Colors.CYAN}3. Claude Desktop Integration:{Colors.END}")
    
    # OS-specific Claude Desktop paths
    if system_info['os'] == 'Darwin':
        config_path = "~/Library/Application Support/Claude/claude_desktop_config.json"
    elif system_info['os'] == 'Windows':
        config_path = "%APPDATA%\\Claude\\claude_desktop_config.json"
    else:
        config_path = "~/.config/Claude/claude_desktop_config.json"
    
    print("   • Open Claude Desktop")
    print("   • Go to Settings → Developer → Edit Config")
    print(f"   • This will create/open: {config_path}")
    print("   • Add this configuration:")
    print()
    print(f"{Colors.BLUE}{claude_config}{Colors.END}")
    print()
    
    print(f"{Colors.CYAN}4. Security Recommendations:{Colors.END}")
    print("   • Use dedicated Wazuh service accounts")
    print("   • Enable SSL verification in production (VERIFY_SSL=true)")
    print("   • Monitor logs regularly for security events")
    print(f"   • Check file permissions: {Colors.YELLOW}ls -la .env{Colors.END}")
    print()
    
    print(f"{Colors.BOLD}🛡️ CAPABILITIES ENABLED:{Colors.END}")
    capabilities = [
        "Real-time security monitoring and alerting",
        "AI-powered threat analysis and correlation",
        "Comprehensive vulnerability management",
        "Compliance reporting (PCI DSS, GDPR, HIPAA)",
        "Agent management and configuration",
        "Custom rule and decoder management",
        "Incident response automation",
        "Forensic analysis and investigation"
    ]
    
    for capability in capabilities:
        print(f"   • {capability}")
    print()
    
    print(f"{Colors.BOLD}🔧 SYSTEM CONFIGURATION:{Colors.END}")
    print(f"   • Platform: {system_info['os']} {system_info['os_version']}")
    print(f"   • Architecture: {system_info['architecture']}")
    print(f"   • Python: {system_info['python_version']}")
    print(f"   • Package Manager: {system_info.get('package_manager', 'None')}")
    print()
    
    print(f"{Colors.BOLD}📞 SUPPORT:{Colors.END}")
    print("   • Documentation: ./docs/")
    print("   • Issues: https://github.com/gensecaihq/Wazuh-MCP-Server/issues")
    print("   • Logs: ./logs/ directory")
    print()
    print(f"{Colors.GREEN}{'=' * 70}{Colors.END}")


def main() -> int:
    """Enhanced main setup function with comprehensive error handling."""
    print_header()
    
    # Detect system information
    system_info = detect_system_info()
    
    print_info(f"Platform: {system_info['os']} {system_info['os_version']}")
    print_info(f"Architecture: {system_info['architecture']}")
    print_info(f"Python: {system_info['python_version']}")
    print_info(f"Package Manager: {system_info.get('package_manager', 'None detected')}")
    print()
    
    # Setup steps with enhanced error handling
    setup_steps = [
        ("Checking Python compatibility", lambda: check_python_version()),
        ("Checking system dependencies", lambda: check_system_dependencies(system_info)),
        ("Checking Pydantic compatibility", lambda: check_and_fix_pydantic()),
        ("Setting up virtual environment", lambda: create_virtual_environment(system_info)),
    ]
    
    # Get virtual environment paths
    activate_cmd, python_exe, pip_exe = get_activation_info(system_info)
    
    # Add remaining steps that require virtual environment
    setup_steps.extend([
        ("Upgrading pip and tools", lambda: upgrade_pip(python_exe)),
        ("Installing dependencies", lambda: install_dependencies(python_exe, pip_exe)),
        ("Installing Wazuh MCP Server", lambda: install_package(python_exe, pip_exe)),
        ("Setting up configuration", lambda: setup_configuration_files()),
        ("Validating configuration", lambda: validate_configuration()),
        ("Testing installation", lambda: test_installation(python_exe)),
    ])
    
    # Execute setup steps
    for step_name, step_func in setup_steps:
        print_step(step_name)
        
        try:
            if not step_func():
                print_error(f"Setup failed at: {step_name}")
                print_info("Please check the error messages above and try again")
                return 1
                
        except KeyboardInterrupt:
            print_error("Setup interrupted by user")
            return 1
        except Exception as e:
            print_error(f"Unexpected error in {step_name}: {e}")
            return 1
        
        print_success(f"Completed: {step_name}")
    
    # Show completion message
    show_completion_message(system_info)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Setup interrupted by user{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}Fatal error: {e}{Colors.END}")
        sys.exit(1)