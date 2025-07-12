#!/usr/bin/env python3
"""
Production-ready installation script for Wazuh MCP Server v1.0.1 hotfix.
Handles Fedora-specific Pydantic V1/V2 compatibility issues.
"""

import os
import sys
import platform
import subprocess
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def detect_platform():
    """Detect current platform and return platform info."""
    system = platform.system().lower()
    
    # Detect if we're on Fedora
    is_fedora = False
    if system == 'linux':
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read().lower()
                is_fedora = 'fedora' in content or 'red hat' in content
        except (FileNotFoundError, PermissionError):
            # Fallback check for Fedora-specific paths
            is_fedora = any([
                os.path.exists('/etc/fedora-release'),
                os.path.exists('/etc/redhat-release'),
                'fedora' in platform.platform().lower()
            ])
    
    return {
        'system': system,
        'is_fedora': is_fedora,
        'is_macos': system == 'darwin',
        'is_ubuntu': 'ubuntu' in platform.platform().lower()
    }


def check_python_version():
    """Check Python version compatibility."""
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 9):
        logger.error(f"Python 3.9+ required, but {version.major}.{version.minor} found")
        return False
    
    logger.info(f"✅ Python {version.major}.{version.minor}.{version.micro} - Compatible")
    return True


def check_and_install_pydantic(platform_info):
    """Check Pydantic version and handle platform-specific installation."""
    try:
        import pydantic  # noqa: F401
        version = getattr(pydantic, '__version__', getattr(pydantic, 'VERSION', 'unknown'))
        
        logger.info(f"📦 Pydantic {version} detected")
        
        if platform_info['is_fedora']:
            if version.startswith('2'):
                logger.warning(f"🐧 Fedora with Pydantic V2 detected - using compatibility mode")
                logger.info("💡 For optimal performance, consider installing V1: pip install 'pydantic>=1.10.0,<2.0.0'")
            else:
                logger.info(f"✅ Pydantic V1 on Fedora - optimal configuration")
        else:
            logger.info(f"✅ Pydantic {version} detected on {platform_info['system']}")
            
        return True
            
    except ImportError:
        logger.warning(f"⚠️  Pydantic not found. Installing...")
        
        if platform_info['is_fedora']:
            # Try system package first on Fedora
            logger.info("🐧 Attempting Fedora system package installation...")
            try:
                subprocess.check_call(['sudo', 'dnf', 'install', '-y', 'python3-pydantic'], 
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                logger.info("✅ Installed via dnf")
                return True
            except (subprocess.CalledProcessError, FileNotFoundError):
                logger.info("📦 System package failed, using pip...")
        
        # Fallback to pip with V1 preference for stability
        try:
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', 'pydantic>=1.10.0,<2.0.0'
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            logger.info("✅ Installed Pydantic V1 via pip")
            return True
        except subprocess.CalledProcessError:
            # If V1 fails, try latest compatible
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', 'pydantic>=1.10.0'
            ])
            logger.info("✅ Installed Pydantic via pip")
            return True


def install_dependencies():
    """Install all required dependencies."""
    logger.info("📦 Installing dependencies...")
    
    try:
        # Install requirements
        requirements_file = Path(__file__).parent / 'requirements.txt'
        if requirements_file.exists():
            subprocess.check_call([
                sys.executable, '-m', 'pip', 'install', '-r', str(requirements_file)
            ], stdout=subprocess.DEVNULL)
            logger.info("✅ Requirements installed")
        
        # Install in development mode
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-e', '.'
        ], stdout=subprocess.DEVNULL)
        logger.info("✅ Package installed in development mode")
        
        return True
        
    except subprocess.CalledProcessError as e:
        logger.error(f"❌ Installation failed: {e}")
        return False


def test_installation(platform_info):
    """Test the installation."""
    logger.info("🧪 Testing installation...")
    
    try:
        # Test basic import
        from wazuh_mcp_server.main import WazuhMCPServer  # noqa: F401
        logger.info("✅ Core import successful")
        
        # Test compatibility layer
        from wazuh_mcp_server.utils.pydantic_compat import BaseModel, validator, PYDANTIC_V2  # noqa: F401
        logger.info(f"✅ Compatibility layer loaded (Pydantic V2: {PYDANTIC_V2})")
        
        # Test validation
        from wazuh_mcp_server.utils.validation import AlertQuery
        query = AlertQuery(limit=50)  # noqa: F841
        logger.info("✅ Validation system working")
        
        # Test configuration
        from wazuh_mcp_server.config import WazuhConfig  # noqa: F401
        logger.info("✅ Configuration system working")
        
        return True
        
    except Exception as e:
        logger.error(f"❌ Import test failed: {e}")
        
        # Platform-specific troubleshooting
        if platform_info['is_fedora']:
            logger.error("🐧 Fedora troubleshooting:")
            logger.error("   1. Try: pip install 'pydantic>=1.10.0,<2.0.0' --force-reinstall")
            logger.error("   2. Check: python3 -c 'import pydantic; print(pydantic.__version__)'")
        
        return False


def create_environment_template():
    """Create .env template file if it doesn't exist."""
    env_file = Path('.env')
    if env_file.exists():
        logger.info("📄 .env file already exists")
        return
    
    template = '''# Wazuh MCP Server v1.0.1 Configuration
# Copy this to .env and fill in your values

# Required Wazuh Server Settings
WAZUH_HOST=your-wazuh-server.com
WAZUH_PORT=55000
WAZUH_USER=your-api-user
WAZUH_PASS=your-secure-password

# SSL Settings (recommended for production)
VERIFY_SSL=true

# Optional: Wazuh Indexer Settings (4.8.0+)
# WAZUH_INDEXER_HOST=your-wazuh-indexer.com
# WAZUH_INDEXER_PORT=9200
# WAZUH_INDEXER_USER=your-indexer-user
# WAZUH_INDEXER_PASS=your-indexer-password

# Optional: External API Keys
# VIRUSTOTAL_API_KEY=your-vt-api-key
# SHODAN_API_KEY=your-shodan-api-key
# ABUSEIPDB_API_KEY=your-abuseipdb-api-key

# Logging
LOG_LEVEL=INFO
DEBUG=false
'''
    
    env_file.write_text(template)
    logger.info("📄 Created .env template file")
    logger.warning("⚠️  Please edit .env file with your Wazuh server details")


def main():
    """Main installation function."""
    logger.info("🔧 Installing Wazuh MCP Server v1.0.1 Hotfix...")
    logger.info("🎯 Fedora Pydantic V1/V2 Compatibility Fix")
    
    # Detect platform
    platform_info = detect_platform()
    logger.info(f"🖥️  Platform: {platform_info['system'].title()}")
    if platform_info['is_fedora']:
        logger.info("🐧 Fedora-specific compatibility enabled")
    
    # Check Python version
    if not check_python_version():
        return 1
    
    # Handle Pydantic installation
    if not check_and_install_pydantic(platform_info):
        return 1
    
    # Install dependencies
    if not install_dependencies():
        return 1
    
    # Test installation
    if not test_installation(platform_info):
        return 1
    
    # Create environment template
    create_environment_template()
    
    # Success message
    logger.info("🎉 Installation completed successfully!")
    logger.info("")
    logger.info("📋 Next steps:")
    logger.info("  1. Edit .env file with your Wazuh server details")
    logger.info("  2. Test connection: python -m wazuh_mcp_server.scripts.test_connection")
    logger.info("  3. Configure Claude Desktop with this server")
    logger.info("")
    logger.info("📚 Documentation: README.md")
    logger.info("🐧 Fedora users: Compatibility layer automatically handles V1/V2")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())