# Installation Guide

This guide covers all installation methods for Wazuh MCP Server v2.1.0 across different platforms.

## 📋 Prerequisites

### System Requirements
- **Python**: 3.11+ (recommended) or 3.9+ (minimum)
- **Operating System**: Windows 10+, macOS 10.15+, or Linux
- **Memory**: 512MB+ available RAM
- **Disk Space**: 100MB+ free space

### Wazuh Requirements
- **Wazuh Server**: 4.8.0 to 4.14.1 (recommended) or 4.0.0+ (minimum with limited features)
- **Network Access**: HTTP/HTTPS connectivity to Wazuh server
- **Credentials**: Valid Wazuh user account with API access
- **Tested Versions**: Fully tested and verified with Wazuh 4.8.0, 4.10.x, 4.12.x, 4.13.x, and 4.14.1

### Claude Desktop
- **Claude Desktop**: Latest version
- **Configuration Access**: Ability to modify Claude Desktop configuration file

## 🚀 Quick Installation

Choose your platform and run the appropriate installer:

### Universal Python Installer (Recommended)
```bash
git clone https://github.com/your-repo/wazuh-mcp-server.git
cd wazuh-mcp-server
python3 installers/install.py
```

### Platform-Specific Installers

#### Windows
```cmd
git clone https://github.com/your-repo/wazuh-mcp-server.git
cd wazuh-mcp-server
installers\platform\install-windows.bat
```

#### macOS
```bash
git clone https://github.com/your-repo/wazuh-mcp-server.git
cd wazuh-mcp-server
chmod +x installers/platform/install-macos.sh
./installers/platform/install-macos.sh
```

#### Debian/Ubuntu/Linux Mint
```bash
git clone https://github.com/your-repo/wazuh-mcp-server.git
cd wazuh-mcp-server
chmod +x installers/platform/install-debian.sh
./installers/platform/install-debian.sh
```

#### Fedora/RHEL/CentOS
```bash
git clone https://github.com/your-repo/wazuh-mcp-server.git
cd wazuh-mcp-server
chmod +x installers/platform/install-fedora.sh
./installers/platform/install-fedora.sh
```

#### Arch Linux/Manjaro
```bash
git clone https://github.com/your-repo/wazuh-mcp-server.git
cd wazuh-mcp-server
chmod +x installers/platform/install-arch.sh
./installers/platform/install-arch.sh
```

## 🔧 Manual Installation

If you prefer manual installation or need more control:

### 1. Clone Repository
```bash
git clone https://github.com/your-repo/wazuh-mcp-server.git
cd wazuh-mcp-server
```

### 2. Create Virtual Environment
```bash
# Create virtual environment
python3 -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
# Upgrade pip
python -m pip install --upgrade pip

# Install requirements
pip install -r requirements.txt
```

### 4. Create Configuration
```bash
# Copy example configuration
cp .env.example .env

# Edit configuration with your Wazuh details
# Windows: notepad .env
# macOS: open -a TextEdit .env
# Linux: nano .env
```

### 5. Test Installation
```bash
# Run health check
./bin/wazuh-mcp-server --health-check
```

## ⚙️ Configuration

### 1. Wazuh Server Configuration

Edit `.env` with your Wazuh server details:

```bash
# Wazuh Server Configuration
WAZUH_HOST=your-wazuh-server.com
WAZUH_PORT=55000
WAZUH_USER=your-username
WAZUH_PASS=your-password

# SSL Configuration (recommended)
VERIFY_SSL=true
ALLOW_SELF_SIGNED=false

# Logging
LOG_LEVEL=INFO

# FastMCP Configuration
MCP_TRANSPORT=stdio
```

### 2. Claude Desktop Configuration

#### Windows
Edit `%APPDATA%\Claude\claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "C:\\path\\to\\wazuh-mcp-server\\bin\\wazuh-mcp-server.exe",
      "args": ["--stdio"]
    }
  }
}
```

#### macOS/Linux
Edit `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/wazuh-mcp-server/bin/wazuh-mcp-server",
      "args": ["--stdio"]
    }
  }
}
```

## ✅ Verification

### 1. Health Check
```bash
./bin/wazuh-mcp-server --health-check
```

Expected output:
```
✅ python_version: Python 3.11.x
✅ dependencies: All dependencies available
✅ config_loading: Configuration loaded successfully
✅ wazuh_connectivity: Connected to Wazuh server at your-server:55000
✅ fastmcp_setup: FastMCP instance created
🎯 Overall health score: 100.0%
```

### 2. Test Connection
```bash
# Activate virtual environment if not already active
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Test basic connectivity
python tools/validate_setup.py
```

### 3. Claude Desktop Test
1. Restart Claude Desktop
2. Ask Claude: "Show me Wazuh system status"
3. You should see connection information and system statistics

## 🔍 Troubleshooting Installation

### Common Issues

#### Python Version Issues
```bash
# Check Python version
python3 --version

# If version is too old, install newer Python:
# Windows: Download from python.org
# macOS: brew install python@3.11
# Ubuntu: sudo apt install python3.11
# Fedora: sudo dnf install python3.11
```

#### Virtual Environment Issues
```bash
# If venv creation fails:
python3 -m pip install --user virtualenv
python3 -m virtualenv venv
```

#### Dependency Installation Issues
```bash
# Clear pip cache and retry
pip cache purge
pip install -r requirements.txt --no-cache-dir

# On macOS, if compiler errors:
xcode-select --install

# On Linux, if missing headers:
sudo apt install python3-dev build-essential  # Debian/Ubuntu
sudo dnf install python3-devel gcc gcc-c++    # Fedora/RHEL
```

#### Permission Issues
```bash
# On Linux/macOS, if permission denied:
chmod +x bin/wazuh-mcp-server
chmod +x installers/platform/*.sh

# On Windows, run as Administrator if needed
```

### Platform-Specific Issues

#### Windows
- **PowerShell Execution Policy**: Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
- **Long Path Issues**: Enable long paths in Windows settings
- **Antivirus**: Add project folder to antivirus exclusions

#### macOS
- **Gatekeeper**: Run `xattr -d com.apple.quarantine bin/wazuh-mcp-server` if blocked
- **Homebrew**: Install Homebrew first for dependencies
- **M1/M2 Macs**: Ensure you're using native Python, not Rosetta

#### Linux
- **SELinux**: Check SELinux policies if connection issues
- **Firewall**: Ensure outbound HTTPS (443) and Wazuh port (55000) are open
- **AppArmor**: May need to configure AppArmor profiles

## 🔄 Upgrading

### From v2.0.x to v2.1.0
```bash
# Backup configuration
cp .env .env.backup

# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Run migration tool
python tools/migrate_v1_to_v2.sh

# Test upgrade
./bin/wazuh-mcp-server --health-check
```

### Clean Installation (if upgrade issues)
```bash
# Remove virtual environment
rm -rf venv

# Reinstall
python3 installers/install.py

# Restore configuration
cp .env.backup .env
```

## 📞 Getting Help

If installation fails:

1. **Check [Troubleshooting Guide](troubleshooting/README.md)**
2. **Run health check** with verbose output: `./bin/wazuh-mcp-server --health-check --verbose`
3. **Check logs** in `logs/` directory
4. **Create an issue** with installation logs and system information

---

**Next Steps**: Once installation is complete, see the [Configuration Guide](configuration.md) for detailed configuration options.