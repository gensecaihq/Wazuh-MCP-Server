#!/usr/bin/env python3
"""
Wazuh MCP Server v2.1.0 - Universal Installer
===========================================
Cross-platform installer for FastMCP STDIO server.
Supports: Windows, macOS, Linux (Debian/Ubuntu, Fedora/RHEL, Arch)
"""

import sys
import os
import subprocess
import platform
import shutil
import json
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Colors for cross-platform terminal output
class Colors:
    RED = '\033[0;31m' if os.name != 'nt' else ''
    GREEN = '\033[0;32m' if os.name != 'nt' else ''
    YELLOW = '\033[1;33m' if os.name != 'nt' else ''
    BLUE = '\033[0;34m' if os.name != 'nt' else ''
    CYAN = '\033[0;36m' if os.name != 'nt' else ''
    NC = '\033[0m' if os.name != 'nt' else ''  # No Color

def print_header():
    """Print installation header."""
    print(f"{Colors.CYAN}╔═══════════════════════════════════════════════════════╗{Colors.NC}")
    print(f"{Colors.CYAN}║           Wazuh MCP Server v2.1.0 Installer          ║{Colors.NC}")
    print(f"{Colors.CYAN}║              FastMCP STDIO Only Edition               ║{Colors.NC}")
    print(f"{Colors.CYAN}╚═══════════════════════════════════════════════════════╝{Colors.NC}")
    print()

def detect_system() -> Dict[str, str]:
    """Detect the operating system and return system information."""
    system_info = {
        'os': platform.system(),
        'arch': platform.machine(),
        'version': platform.version(),
        'python_version': platform.python_version(),
        'distribution': None,
        'package_manager': None
    }
    
    # Detect Linux distribution
    if system_info['os'] == 'Linux':
        try:
            with open('/etc/os-release', 'r') as f:
                os_release = f.read()
                if 'ubuntu' in os_release.lower() or 'debian' in os_release.lower() or 'mint' in os_release.lower():
                    system_info['distribution'] = 'debian'
                    system_info['package_manager'] = 'apt'
                elif 'fedora' in os_release.lower() or 'rhel' in os_release.lower() or 'centos' in os_release.lower():
                    system_info['distribution'] = 'fedora'
                    system_info['package_manager'] = 'dnf'
                elif 'arch' in os_release.lower() or 'manjaro' in os_release.lower():
                    system_info['distribution'] = 'arch'
                    system_info['package_manager'] = 'pacman'
        except FileNotFoundError:
            system_info['distribution'] = 'unknown'
    
    return system_info

def check_python_version() -> bool:
    """Check if Python version meets requirements."""
    required_version = (3, 11)
    current_version = sys.version_info[:2]
    
    if current_version >= required_version:
        print(f"{Colors.GREEN}✅ Python {'.'.join(map(str, current_version))} meets requirements{Colors.NC}")
        return True
    else:
        print(f"{Colors.RED}❌ Python {'.'.join(map(str, required_version))}+ required, found {'.'.join(map(str, current_version))}{Colors.NC}")
        return False

def run_command(command: List[str], check: bool = True) -> Tuple[bool, str]:
    """Run a system command and return success status and output."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=check)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr
    except FileNotFoundError:
        return False, f"Command not found: {command[0]}"

def create_virtual_environment() -> bool:
    """Create a Python virtual environment."""
    venv_path = Path("venv")
    
    if venv_path.exists():
        print(f"{Colors.YELLOW}📁 Virtual environment already exists{Colors.NC}")
        return True
    
    print(f"{Colors.BLUE}🐍 Creating Python virtual environment...{Colors.NC}")
    success, output = run_command([sys.executable, '-m', 'venv', 'venv'])
    
    if success:
        print(f"{Colors.GREEN}✅ Virtual environment created{Colors.NC}")
        return True
    else:
        print(f"{Colors.RED}❌ Failed to create virtual environment: {output}{Colors.NC}")
        return False

def get_pip_command() -> List[str]:
    """Get the appropriate pip command for the current platform."""
    if platform.system() == 'Windows':
        return [str(Path("venv") / "Scripts" / "pip.exe")]
    else:
        return [str(Path("venv") / "bin" / "pip")]

def install_python_dependencies() -> bool:
    """Install Python dependencies in the virtual environment."""
    print(f"{Colors.BLUE}📚 Installing Python dependencies...{Colors.NC}")
    
    pip_cmd = get_pip_command()
    
    # Upgrade pip
    success, output = run_command(pip_cmd + ['install', '--upgrade', 'pip'])
    if not success:
        print(f"{Colors.RED}❌ Failed to upgrade pip: {output}{Colors.NC}")
        return False
    
    # Install requirements
    success, output = run_command(pip_cmd + ['install', '-r', 'requirements.txt'])
    if success:
        print(f"{Colors.GREEN}✅ Python dependencies installed{Colors.NC}")
        return True
    else:
        print(f"{Colors.RED}❌ Failed to install dependencies: {output}{Colors.NC}")
        return False

def create_config_file() -> bool:
    """Create configuration file."""
    print(f"{Colors.BLUE}⚙️  Creating configuration file...{Colors.NC}")
    
    env_file = Path(".env")
    if not env_file.exists():
        env_content = """# Wazuh MCP Server v2.1.0 Configuration
# FastMCP STDIO Edition

# Wazuh Server Configuration
WAZUH_HOST=localhost
WAZUH_PORT=55000
WAZUH_USER=wazuh
WAZUH_PASS=changeme

# SSL Configuration
VERIFY_SSL=false
ALLOW_SELF_SIGNED=true

# Logging Configuration
LOG_LEVEL=INFO

# FastMCP Configuration
MCP_TRANSPORT=stdio
"""
        env_file.write_text(env_content)
        print(f"{Colors.GREEN}✅ Configuration file created: .env{Colors.NC}")
    else:
        print(f"{Colors.YELLOW}📁 Configuration file already exists{Colors.NC}")
    
    return True

def create_claude_desktop_config() -> Tuple[str, str]:
    """Create Claude Desktop configuration example."""
    current_dir = Path.cwd().absolute()
    
    if platform.system() == 'Windows':
        python_path = str(current_dir / "venv" / "Scripts" / "python.exe")
        config_path = "%APPDATA%\\Claude\\claude_desktop_config.json"
    else:
        python_path = str(current_dir / "venv" / "bin" / "python")
        config_path = "~/.config/claude/claude_desktop_config.json"
    
    config = {
        "mcpServers": {
            "wazuh": {
                "command": python_path,
                "args": [str(current_dir / "bin" / "wazuh-mcp-server"), "--stdio"]
            }
        }
    }
    
    config_json = json.dumps(config, indent=2)
    
    # Save example config
    example_file = Path("claude-desktop-config-example.json")
    example_file.write_text(config_json)
    
    return config_path, config_json

def test_installation() -> bool:
    """Test the installation."""
    print(f"{Colors.BLUE}🧪 Testing installation...{Colors.NC}")
    
    # Test Python executable
    if platform.system() == 'Windows':
        python_path = Path("venv") / "Scripts" / "python.exe"
    else:
        python_path = Path("venv") / "bin" / "python"
    
    # Test server import
    test_cmd = [str(python_path), "-c", "import sys; sys.path.insert(0, 'src'); from wazuh_mcp_server.server import mcp; print('FastMCP server available')"]
    success, output = run_command(test_cmd, check=False)
    
    if success:
        print(f"{Colors.GREEN}✅ Installation test passed{Colors.NC}")
        return True
    else:
        print(f"{Colors.RED}❌ Installation test failed: {output}{Colors.NC}")
        return False

def print_next_steps(config_path: str, config_json: str):
    """Print next steps for the user."""
    print(f"\n{Colors.GREEN}🎉 Installation completed successfully!{Colors.NC}")
    print(f"\n{Colors.CYAN}📝 Next Steps:{Colors.NC}")
    print(f"1. {Colors.YELLOW}Configure Wazuh credentials:{Colors.NC}")
    print(f"   Edit the .env file with your Wazuh server details")
    print(f"\n2. {Colors.YELLOW}Configure Claude Desktop:{Colors.NC}")
    print(f"   Add this to {config_path}:")
    print(f"{Colors.BLUE}{config_json}{Colors.NC}")
    print(f"\n3. {Colors.YELLOW}Start using the server:{Colors.NC}")
    print(f"   Restart Claude Desktop and ask: 'Show me Wazuh alerts'")
    print(f"\n{Colors.BLUE}💡 Pro Tips:{Colors.NC}")
    print(f"• Test the server: {Colors.YELLOW}./bin/wazuh-mcp-server --stdio{Colors.NC}")
    print(f"• Run health check: {Colors.YELLOW}./bin/wazuh-mcp-server --health-check{Colors.NC}")
    print(f"• Check documentation: {Colors.YELLOW}docs/{Colors.NC}")

def main():
    """Main installation function."""
    print_header()
    
    # Detect system
    system_info = detect_system()
    print(f"{Colors.BLUE}🖥️  Detected: {system_info['os']} {system_info['arch']}")
    if system_info['distribution']:
        print(f"    Distribution: {system_info['distribution']} ({system_info['package_manager']})")
    print(f"    Python: {system_info['python_version']}{Colors.NC}")
    print()
    
    # Check Python version
    if not check_python_version():
        print(f"\n{Colors.RED}❌ Installation aborted due to Python version requirements{Colors.NC}")
        print(f"Please install Python 3.11+ and try again")
        sys.exit(1)
    
    # Create virtual environment
    if not create_virtual_environment():
        print(f"\n{Colors.RED}❌ Installation aborted due to virtual environment issues{Colors.NC}")
        sys.exit(1)
    
    # Install Python dependencies
    if not install_python_dependencies():
        print(f"\n{Colors.RED}❌ Installation aborted due to Python dependency issues{Colors.NC}")
        sys.exit(1)
    
    # Create configuration
    if not create_config_file():
        print(f"\n{Colors.RED}❌ Installation aborted due to configuration issues{Colors.NC}")
        sys.exit(1)
    
    # Create Claude Desktop config example
    config_path, config_json = create_claude_desktop_config()
    
    # Test installation
    if not test_installation():
        print(f"\n{Colors.YELLOW}⚠️  Installation completed with warnings{Colors.NC}")
    
    # Print next steps
    print_next_steps(config_path, config_json)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}⚠️  Installation cancelled by user{Colors.NC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.RED}❌ Installation failed with error: {e}{Colors.NC}")
        sys.exit(1)