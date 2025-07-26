# 🐳 Docker Installation Guide

Complete Docker installation guide for all supported operating systems with automated scripts and manual instructions.

## 🚀 Automated Installation (Recommended)

### 🐧 Linux Systems

**Debian/Ubuntu (and derivatives):**
```bash
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-debian.sh | bash
```

**RHEL/CentOS/Fedora/Rocky/AlmaLinux:**
```bash
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-redhat.sh | bash
```

### 🍎 macOS

**Automated Installation:**
```bash
curl -fsSL https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-macos.sh | bash
```

### 🪟 Windows

**PowerShell (Run as Administrator):**
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
iwr -useb https://raw.githubusercontent.com/gensecaihq/Wazuh-MCP-Server/main/scripts/install-docker-windows.ps1 | iex
```

## 📋 What the Scripts Install

### All Platforms
- ✅ **Docker Engine** - Latest stable version
- ✅ **Docker Compose** - V2 plugin or standalone
- ✅ **Wazuh MCP Server** - Complete project setup
- ✅ **System Configuration** - Optimized Docker settings
- ✅ **Verification Tools** - Installation testing
- ✅ **Deployment Scripts** - Ready-to-use deployment helpers

### Platform-Specific Features

#### Linux (Debian/Ubuntu)
- ✅ Official Docker APT repository
- ✅ User group configuration
- ✅ Systemd service enablement
- ✅ Security hardening
- ✅ Automatic startup configuration

#### Linux (RHEL/CentOS/Fedora)
- ✅ Official Docker YUM/DNF repository
- ✅ SELinux configuration
- ✅ Firewalld configuration
- ✅ User group configuration
- ✅ Systemd service enablement

#### macOS
- ✅ Docker Desktop installation
- ✅ Homebrew integration
- ✅ Architecture detection (Intel/Apple Silicon)
- ✅ System requirements verification
- ✅ Claude Desktop integration helper

#### Windows
- ✅ Docker Desktop with WSL2 backend
- ✅ Windows feature enablement
- ✅ Hyper-V/WSL2 configuration
- ✅ PowerShell execution policy management
- ✅ Claude Desktop integration helper

## 🔧 Manual Installation

If you prefer manual installation or need custom configuration:

### Prerequisites

#### All Platforms
- **Memory**: 2GB minimum (4GB recommended for Windows/macOS)
- **Storage**: 5GB available space (10GB for Windows/macOS)
- **Network**: Internet connection for downloads

#### Linux Specific
- Kernel version 3.10+ (4.0+ recommended)
- 64-bit architecture
- Virtualization support

#### Windows Specific
- Windows 10 Pro/Enterprise/Education (build 19041+) or Windows 11
- Hyper-V or WSL2 support
- Administrator privileges

#### macOS Specific
- macOS 10.15+ (Catalina or later)
- 4GB RAM minimum
- VirtualBox not recommended with Docker Desktop

### Manual Docker Installation Steps

#### Ubuntu/Debian
```bash
# Update package index
sudo apt-get update

# Install prerequisites
sudo apt-get install -y apt-transport-https ca-certificates curl gnupg lsb-release

# Add Docker GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg

# Add Docker repository
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Configure user permissions
sudo usermod -aG docker $USER

# Start and enable Docker
sudo systemctl enable docker
sudo systemctl start docker
```

#### RHEL/CentOS/Fedora
```bash
# Install prerequisites
sudo dnf install -y yum-utils device-mapper-persistent-data lvm2

# Add Docker repository
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# Install Docker
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin

# Configure user permissions
sudo usermod -aG docker $USER

# Start and enable Docker
sudo systemctl enable docker
sudo systemctl start docker
```

#### macOS
1. Download Docker Desktop from [docker.com](https://www.docker.com/products/docker-desktop)
2. Install Docker Desktop by dragging to Applications
3. Start Docker Desktop
4. Complete the setup wizard

#### Windows
1. Download Docker Desktop from [docker.com](https://www.docker.com/products/docker-desktop)
2. Run the installer as Administrator
3. Choose WSL2 backend (recommended)
4. Restart when prompted
5. Complete Docker Desktop setup

## 🔍 Verification

After installation, verify your setup:

```bash
# Run verification script
./scripts/verify-installation.sh

# Manual verification
docker --version
docker compose version
docker run hello-world
```

## 🛠️ Troubleshooting

### Common Issues

#### Linux: Permission Denied
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Log out and back in, or run:
newgrp docker
```

#### Linux: Docker daemon not running
```bash
# Start Docker service
sudo systemctl start docker

# Enable automatic startup
sudo systemctl enable docker
```

#### macOS: Docker Desktop won't start
- Check system requirements (macOS 10.15+, 4GB RAM)
- Ensure VirtualBox is not running
- Try restarting your Mac
- Check Docker Desktop logs in Console app

#### Windows: WSL2 kernel not found
```powershell
# Download and install WSL2 kernel update
wsl --update
wsl --set-default-version 2
```

#### Windows: Hyper-V conflicts
- Disable VirtualBox if installed
- Ensure Hyper-V is properly enabled
- Check Windows edition compatibility

### Performance Optimization

#### Linux
```bash
# Configure Docker daemon
sudo tee /etc/docker/daemon.json > /dev/null <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "100m",
    "max-file": "3"
  },
  "storage-driver": "overlay2"
}
EOF

sudo systemctl restart docker
```

#### macOS/Windows
- Allocate sufficient memory (4GB minimum)
- Enable BuildKit for faster builds
- Use WSL2 backend on Windows for better performance

## 🎯 Next Steps

After successful Docker installation:

1. **Clone the Wazuh MCP Server project:**
   ```bash
   git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
   cd Wazuh-MCP-Server
   ```

2. **Configure your Wazuh connection:**
   ```bash
   python3 configure.py
   ```

3. **Deploy the server:**
   ```bash
   docker compose up -d
   ```

4. **Verify functionality:**
   ```bash
   python3 test-functionality.py
   ```

5. **Integrate with Claude Desktop:**
   - See [README.md](README.md) for MCP client configuration
   - Use the generated helper scripts for your platform

## 📚 Additional Resources

- **Docker Documentation**: [docs.docker.com](https://docs.docker.com)
- **Docker Compose**: [docs.docker.com/compose](https://docs.docker.com/compose)
- **Wazuh MCP Server**: [README.md](README.md)
- **Production Deployment**: [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md)
- **Support**: [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)

## 🔒 Security Considerations

- Always use official Docker repositories
- Keep Docker updated to the latest stable version
- Run containers as non-root users when possible
- Use Docker secrets for sensitive configuration
- Regularly scan images for vulnerabilities
- Configure proper firewall rules
- Enable Docker Content Trust in production

## 🏆 Best Practices

- Use multi-stage builds for smaller images
- Leverage Docker layer caching
- Set resource limits on containers
- Use health checks for better monitoring
- Implement proper logging strategy
- Use .dockerignore to exclude unnecessary files
- Tag images with semantic versions
- Use Docker Compose for multi-container applications