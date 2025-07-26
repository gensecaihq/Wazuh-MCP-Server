# 🚀 Installation Scripts

This directory contains automated installation scripts for setting up Docker and the Wazuh MCP Server on various operating systems.

## 📁 Available Scripts

### Platform-Specific Docker Installation

- **`install-docker-debian.sh`** - Debian/Ubuntu/Mint/Pop!_OS systems
- **`install-docker-redhat.sh`** - RHEL/CentOS/Fedora/Rocky/AlmaLinux systems  
- **`install-docker-macos.sh`** - macOS (Intel & Apple Silicon)
- **`install-docker-windows.ps1`** - Windows 10/11 with WSL2

### Verification & Testing

- **`verify-installation.sh`** - Cross-platform installation verification

## 🔧 Usage

### Quick Install (Recommended)

**Linux (Debian/Ubuntu):**
```bash
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/install/install-docker-debian.sh | bash
```

**Linux (RHEL/CentOS/Fedora):**
```bash
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/install/install-docker-redhat.sh | bash
```

**macOS:**
```bash
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/install/install-docker-macos.sh | bash
```

**Windows (PowerShell as Administrator):**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
iwr -useb https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/install/install-docker-windows.ps1 | iex
```

### Local Installation

```bash
# Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Make scripts executable
chmod +x install/*.sh

# Run appropriate script for your platform
./install/install-docker-debian.sh     # For Debian/Ubuntu
./install/install-docker-redhat.sh     # For RHEL/CentOS/Fedora
./install/install-docker-macos.sh      # For macOS
# For Windows, run in PowerShell as Administrator:
# .\install\install-docker-windows.ps1
```

### Verification

```bash
# Verify complete installation
./install/verify-installation.sh

# Quick verification
docker --version
docker compose version
docker run hello-world
```

## ✅ What Gets Installed

### All Platforms
- ✅ **Docker Engine** (latest stable version)
- ✅ **Docker Compose** (V2 plugin)
- ✅ **Wazuh MCP Server** (complete project setup)
- ✅ **System Configuration** (optimized settings, user permissions)

### Platform-Specific
- **Linux**: Repository setup, GPG keys, systemd services
- **macOS**: Homebrew (if needed), Docker Desktop, architecture detection
- **Windows**: WSL2 setup, Docker Desktop, Windows feature enablement

## 🔒 Security Features

- **GPG Verification**: All Docker repositories verified with official GPG keys
- **Official Sources**: Only official Docker, Homebrew, and Microsoft repositories used
- **User Permissions**: Proper Docker group management and sudo validation
- **System Checks**: Prerequisites and compatibility verification before installation

## 🛠️ Troubleshooting

If installation fails, see:
- [Docker Installation Guide](../docs/guides/DOCKER_INSTALLATION_GUIDE.md#troubleshooting)
- Run `./install/verify-installation.sh` for diagnostic information
- Check platform-specific requirements in the main README

## 📋 Requirements

### Minimum System Requirements
- **RAM**: 2GB (4GB recommended)
- **Disk**: 5GB free space (10GB recommended)
- **Network**: Internet connection for downloading packages

### Platform Requirements
- **Linux**: sudo access, systemd (for service management)
- **macOS**: macOS 10.15+ (Catalina), admin privileges
- **Windows**: Windows 10 Pro/Enterprise/Education or Windows 11, admin privileges