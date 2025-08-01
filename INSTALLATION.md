# Wazuh MCP Remote Server - Complete Installation Guide

A comprehensive, step-by-step guide for deploying the Wazuh MCP Remote Server with complete OS-agnostic Docker support.

> **Branch**: `mcp-remote` - Production-ready remote MCP server implementation

## 🌐 Branch Information

This installation guide is for the **`mcp-remote`** branch, which provides:
- ✅ Full MCP protocol compliance (2025-03-26 specification)
- ✅ Remote server with SSE transport
- ✅ 29 specialized security tools
- ✅ Production-grade security hardening
- ✅ Enterprise deployment readiness

## 📋 Table of Contents

1. [Prerequisites](#-prerequisites)
2. [Pre-Deployment](#-pre-deployment)
3. [Installation Methods](#-installation-methods)
4. [Deployment](#-deployment)
5. [Post-Deployment](#-post-deployment)
6. [Claude Desktop Integration](#-claude-desktop-integration)
7. [Verification & Testing](#-verification--testing)
8. [Troubleshooting](#-troubleshooting)

## 🔧 Prerequisites

### System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 1 core | 2+ cores |
| **Memory** | 1GB RAM | 2GB+ RAM |
| **Storage** | 2GB free | 5GB+ free |
| **Network** | Internet access | Stable connection |

### Supported Operating Systems

✅ **Linux Distributions:**
- Ubuntu 18.04+ / Debian 9+
- CentOS 7+ / RHEL 7+ / Rocky Linux
- Fedora 32+
- Alpine Linux 3.12+
- Amazon Linux 2

✅ **macOS:**
- macOS 10.15 (Catalina) or newer
- Intel or Apple Silicon (M1/M2)

✅ **Windows:**
- Windows 10/11 with WSL2
- Windows Server 2019+

### Required Software

- **Docker Engine** 20.10.0+ with Compose v2.20+
- **curl** (for health checks)
- **jq** (for JSON processing)
- **openssl** (for key generation)

## 🚀 Pre-Deployment

### Step 1: Download and Prepare

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Switch to mcp-remote branch
git checkout mcp-remote

# Make installer executable
chmod +x install.sh

# Verify repository contents
ls -la
```

### Step 2: Wazuh Server Prerequisites

Before installation, ensure you have:

#### 🔑 Wazuh API Credentials
- **Wazuh Server URL** (e.g., `https://wazuh.company.com`)
- **API Username** with appropriate permissions
- **API Password**
- **API Port** (default: 55000)

#### 🛡️ Wazuh API User Setup
Create a dedicated API user with minimal required permissions:

```bash
# On your Wazuh server, create API user
sudo /var/ossec/bin/wazuh-authd -k your-key

# Or use Wazuh dashboard to create API user with permissions:
# - agents:read
# - manager:read
# - cluster:read
# - rules:read
# - decoders:read
```

#### 🌐 Network Requirements
- **Outbound HTTPS** access to Wazuh server (port 55000)
- **Inbound HTTP** access for MCP server (port 3000)
- **Docker Hub** access for image downloads

### Step 3: Firewall Configuration

#### Linux (Ubuntu/Debian)
```bash
# Allow MCP server port
sudo ufw allow 3000/tcp
sudo ufw reload
```

#### Linux (CentOS/RHEL)
```bash
# Allow MCP server port
sudo firewall-cmd --permanent --add-port=3000/tcp
sudo firewall-cmd --reload
```

#### macOS
```bash
# No additional configuration needed (application firewall)
```

## 📦 Installation Methods

### Method 1: Intelligent Installer (Recommended)

The automated installer handles everything including Docker installation, system checks, and configuration.

#### Interactive Installation
```bash
# Run interactive installer
./install.sh

# Follow the prompts:
# 1. System detection and requirements check
# 2. Docker installation (if needed)
# 3. Wazuh server configuration
# 4. SSL and authentication setup
# 5. Automated deployment
# 6. API key generation
```

#### Non-Interactive Installation
```bash
# Set environment variables
export WAZUH_HOST="https://your-wazuh-server.com"
export WAZUH_USER="your-api-user"
export WAZUH_PASS="your-api-password"
export MCP_PORT="3000"

# Run automated installation
./install.sh --non-interactive
```

#### Advanced Installation Options
```bash
# Configuration only (no deployment)
./install.sh --config-only

# Deployment only (requires existing .env)
./install.sh --deploy-only

# Skip Docker installation
./install.sh --skip-docker-install

# Show help
./install.sh --help
```

### Method 2: Manual Installation

For advanced users who prefer manual control over each step.

#### Step 1: Install Docker

**Ubuntu/Debian:**
```bash
# Remove old versions
sudo apt-get remove docker docker-engine docker.io containerd runc

# Install dependencies
sudo apt-get update
sudo apt-get install ca-certificates curl gnupg lsb-release

# Add Docker GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Set up repository
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker
sudo apt-get update
sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

**CentOS/RHEL:**
```bash
# Install yum-utils
sudo yum install -y yum-utils

# Add Docker repository
sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# Install Docker
sudo yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin

# Start and enable
sudo systemctl start docker
sudo systemctl enable docker
sudo usermod -aG docker $USER
```

**macOS:**
```bash
# Download and install Docker Desktop from:
# https://docs.docker.com/desktop/mac/install/

# Verify installation
docker --version
docker compose version
```

#### Step 2: Manual Configuration

```bash
# Copy environment template
cp .env.example .env

# Edit configuration
nano .env
```

**Required Configuration:**
```env
# Wazuh Server Connection
WAZUH_HOST=https://your-wazuh-server.com
WAZUH_USER=your-api-user
WAZUH_PASS=your-api-password
WAZUH_PORT=55000

# MCP Server Configuration
MCP_HOST=0.0.0.0
MCP_PORT=3000

# Authentication (generate with: openssl rand -hex 32)
AUTH_SECRET_KEY=your-64-character-hex-key

# CORS Configuration
ALLOWED_ORIGINS=https://claude.ai,http://localhost:*

# SSL Configuration  
WAZUH_VERIFY_SSL=false
WAZUH_ALLOW_SELF_SIGNED=true

# Logging
LOG_LEVEL=INFO
```

#### Step 3: Secure Configuration
```bash
# Set secure permissions
chmod 600 .env

# Generate API key for client authentication
echo "MCP_API_KEY=wazuh_$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-32)" > .api_key
chmod 600 .api_key
```

## 🚀 Deployment

### Step 1: Pre-Deployment Verification

```bash
# Test Wazuh connectivity
source .env
curl -u "$WAZUH_USER:$WAZUH_PASS" --insecure "$WAZUH_HOST:$WAZUH_PORT/"

# Check Docker
docker --version
docker compose version
docker info

# Verify system resources
free -h    # Memory
df -h .    # Disk space
```

### Step 2: Build and Deploy

```bash
# Set build metadata
export BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
export VERSION="4.0.0"

# Build the container image
docker compose build --pull --parallel --progress=auto

# Deploy the service
docker compose up -d --wait --wait-timeout 120

# Verify deployment
docker compose ps
```

### Step 3: Monitor Deployment

```bash
# Follow logs during startup
docker compose logs -f wazuh-mcp-server

# Check container health
docker inspect wazuh-mcp-server --format='{{.State.Health.Status}}'

# Monitor resource usage
docker stats wazuh-mcp-server --no-stream
```

## ✅ Post-Deployment

### Step 1: Health Verification

```bash
# Basic health check
curl -f http://localhost:3000/health

# Detailed health with JSON
curl -H "Accept: application/json" http://localhost:3000/health | jq

# MCP protocol test
curl -H "Origin: https://claude.ai" -H "Accept: application/json" http://localhost:3000/

# Metrics endpoint
curl http://localhost:3000/metrics
```

### Step 2: Security Verification

```bash
# Check running processes
docker compose exec wazuh-mcp-server ps aux

# Verify non-root execution
docker compose exec wazuh-mcp-server id

# Check file permissions
ls -la .env .api_key

# Network connectivity test
docker compose exec wazuh-mcp-server nc -zv ${WAZUH_HOST#https://} 55000
```

### Step 3: Performance Baseline

```bash
# Container resource usage
docker stats wazuh-mcp-server --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"

# Response time test
time curl -s http://localhost:3000/health > /dev/null

# Load test (optional)
for i in {1..10}; do
  curl -s http://localhost:3000/health > /dev/null &
done
wait
```

## 🤝 Claude Desktop Integration

### Step 1: Obtain API Key

```bash
# Get your API key
cat .api_key

# Or generate a new one
echo "MCP_API_KEY=wazuh_$(openssl rand -base64 32 | tr -d '=+/' | cut -c1-32)" > .api_key
```

### Step 2: Configure Claude Desktop

#### macOS Configuration
```bash
# Open Claude Desktop configuration
open ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

#### Windows Configuration
```bash
# Navigate to configuration directory
%APPDATA%\Claude\claude_desktop_config.json
```

#### Linux Configuration
```bash
# Open configuration file
~/.config/Claude/claude_desktop_config.json
```

### Step 3: Add MCP Server Configuration

```json
{
  "mcpServers": {
    "wazuh-remote": {
      "url": "http://localhost:3000/sse",
      "headers": {
        "Authorization": "Bearer your-jwt-token-here"
      }
    }
  }
}
```

> **Important**: 
> - Remote MCP servers **must** use the `/sse` endpoint as per Anthropic standards
> - The URL **must** end with `/sse` for proper SSE transport
> - Authentication is **required** using Bearer tokens
> - Get your JWT token from: `POST http://localhost:3000/auth/token`

### Getting Your Authentication Token

Before configuring Claude Desktop, get your authentication token:

```bash
# Get your JWT token
curl -X POST http://localhost:3000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "your-api-key-from-server-logs"}'

# Response will include the bearer token
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 86400
}
```

**For Production Deployment:**
```json
{
  "mcpServers": {
    "wazuh-remote": {
      "url": "https://your-server-domain.com/sse",
      "headers": {
        "Authorization": "Bearer your-jwt-token-here"
      }
    }
  }
}
```

### Step 4: Alternative Integration Methods

#### Direct HTTP Integration
```json
{
  "mcpServers": {
    "wazuh-http": {
      "command": "curl",
      "args": [
        "-X", "POST",
        "-H", "Content-Type: application/json",
        "-H", "Authorization: Bearer YOUR_API_KEY",
        "http://localhost:3000/",
        "--data-binary", "@-"
      ]
    }
  }
}
```

#### SSE Stream Integration
```json
{
  "mcpServers": {
    "wazuh-sse": {
      "transport": {
        "type": "sse",
        "url": "http://localhost:3000/",
        "headers": {
          "Authorization": "Bearer YOUR_API_KEY",
          "Origin": "https://claude.ai"
        }
      }
    }
  }
}
```

### Step 5: Test Claude Integration

1. **Restart Claude Desktop** after configuration changes
2. **Test connection** by asking Claude about Wazuh
3. **Verify tools** are available in Claude interface
4. **Check logs** for any connection issues

```bash
# Monitor server logs during Claude testing
docker compose logs -f wazuh-mcp-server
```

## 🔍 Verification & Testing

### Comprehensive Test Suite

```bash
# 1. Service availability
curl -f http://localhost:3000/health

# 2. MCP protocol compliance
curl -X POST http://localhost:3000/ \
  -H "Content-Type: application/json" \
  -H "Origin: https://claude.ai" \
  -d '{"jsonrpc":"2.0","id":"test","method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"Test","version":"1.0"}}}'

# 3. Tools discovery
curl -X POST http://localhost:3000/ \
  -H "Content-Type: application/json" \
  -H "Origin: https://claude.ai" \
  -d '{"jsonrpc":"2.0","id":"tools","method":"tools/list","params":{}}'

# 4. Authentication test
API_KEY=$(cat .api_key | cut -d= -f2)
curl -X POST http://localhost:3000/auth/token \
  -H "Content-Type: application/json" \
  -d "{\"api_key\":\"$API_KEY\"}"

# 5. Wazuh connectivity test
curl -X POST http://localhost:3000/ \
  -H "Content-Type: application/json" \
  -H "Origin: https://claude.ai" \
  -d '{"jsonrpc":"2.0","id":"wazuh-test","method":"tools/call","params":{"name":"get_wazuh_info","arguments":{}}}'
```

### Load Testing (Optional)

```bash
# Install Apache Bench (if not available)
# Ubuntu: sudo apt-get install apache2-utils
# macOS: brew install httpie

# Basic load test
ab -n 100 -c 10 http://localhost:3000/health

# Sustained load test
for i in {1..60}; do
  curl -s http://localhost:3000/health > /dev/null
  sleep 1
done
```

## 🚨 Troubleshooting

### Common Issues and Solutions

#### 1. Docker Installation Problems

**Issue:** Docker daemon not running
```bash
# Linux
sudo systemctl start docker
sudo systemctl status docker

# macOS  
# Start Docker Desktop application

# Check Docker version
docker --version
```

**Issue:** Permission denied
```bash
# Add user to docker group
sudo usermod -aG docker $USER
# Logout and login again

# Or use sudo temporarily
sudo docker compose up -d
```

#### 2. Configuration Issues

**Issue:** Wazuh connection failed
```bash
# Test Wazuh connectivity manually
curl -v -u "$WAZUH_USER:$WAZUH_PASS" --insecure "$WAZUH_HOST:$WAZUH_PORT/"

# Check SSL settings
echo "WAZUH_VERIFY_SSL=false" >> .env
echo "WAZUH_ALLOW_SELF_SIGNED=true" >> .env
```

**Issue:** Invalid configuration
```bash
# Validate environment file
source .env
echo "Wazuh Host: $WAZUH_HOST"
echo "API User: $WAZUH_USER"
echo "MCP Port: $MCP_PORT"

# Regenerate configuration
rm .env
./install.sh --config-only
```

#### 3. Deployment Problems

**Issue:** Container won't start
```bash
# Check container logs
docker compose logs wazuh-mcp-server

# Check container status
docker compose ps

# Rebuild container
docker compose down
docker compose build --no-cache
docker compose up -d
```

**Issue:** Port already in use
```bash
# Find process using port 3000
sudo lsof -i :3000
# Or
sudo netstat -tulpn | grep 3000

# Kill the process or change port
export MCP_PORT=3001
docker compose up -d
```

#### 4. Claude Integration Issues

**Issue:** Claude can't connect to MCP server
```bash
# Verify MCP server is accessible
curl -H "Origin: https://claude.ai" http://localhost:3000/

# Check Claude Desktop logs (macOS)
tail -f ~/Library/Logs/Claude/claude_desktop.log

# Verify API key
cat .api_key
```

**Issue:** MCP tools not appearing in Claude
```bash
# Test tools endpoint
curl -X POST http://localhost:3000/ \
  -H "Content-Type: application/json" \
  -H "Origin: https://claude.ai" \
  -d '{"jsonrpc":"2.0","id":"tools","method":"tools/list","params":{}}'

# Restart Claude Desktop completely
# Kill process and restart application
```

#### 5. Performance Issues

**Issue:** Slow response times
```bash
# Check container resources
docker stats wazuh-mcp-server

# Check system resources
top
free -h
df -h

# Increase container limits in compose.yml
```

**Issue:** Memory usage high
```bash
# Monitor memory usage
docker stats --format "table {{.Container}}\t{{.MemUsage}}"

# Reduce memory usage
export LOG_LEVEL=WARNING
docker compose restart
```

### Advanced Troubleshooting

#### Debug Mode
```bash
# Enable debug logging
echo "LOG_LEVEL=DEBUG" >> .env
docker compose restart

# Follow debug logs
docker compose logs -f --tail=100
```

#### Health Check Details
```bash
# Manual health check with details
curl -v http://localhost:3000/health

# Check all endpoints
curl http://localhost:3000/         # MCP endpoint
curl http://localhost:3000/metrics  # Metrics
curl http://localhost:3000/docs     # API docs
```

#### Network Diagnostics
```bash
# Test from inside container
docker compose exec wazuh-mcp-server curl -v http://localhost:3000/health

# Test Wazuh connectivity from container
docker compose exec wazuh-mcp-server curl -v --insecure $WAZUH_HOST:$WAZUH_PORT/
```

### Getting Help

If you encounter issues not covered here:

1. **Check logs**: `docker compose logs -f`
2. **Review configuration**: Ensure all required variables are set
3. **Test connectivity**: Verify network access to Wazuh server
4. **Update components**: Ensure Docker and images are up-to-date
5. **Community support**: 
   - GitHub Issues: https://github.com/gensecaihq/Wazuh-MCP-Server/issues
   - Discussions: https://github.com/gensecaihq/Wazuh-MCP-Server/discussions

## 📚 Additional Resources

- **Main README**: [README.md](README.md)
- **API Documentation**: Available at http://localhost:3000/docs
- **MCP Specification**: https://modelcontextprotocol.io/
- **Wazuh Documentation**: https://documentation.wazuh.com/
- **Docker Documentation**: https://docs.docker.com/

---

**Installation Guide v4.0.0** | Built with ❤️ by [GenSec AI](https://github.com/gensecaihq)