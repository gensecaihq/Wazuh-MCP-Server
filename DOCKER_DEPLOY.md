# 🐳 Docker Deployment Guide

**Complete OS-Agnostic Deployment** - Run Wazuh MCP Server anywhere Docker runs!

## 🚀 Quick Start (3 Steps)

### Step 1: Get the Code
```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
```

### Step 2: Configure Wazuh Connection
```bash
./configure-wazuh.sh
```
*This interactive script will collect your Wazuh Manager details and create the configuration.*

### Step 3: Access Your Server
Your server is now running at:
- **HTTP/SSE Mode**: http://localhost:3000
- **Health Check**: http://localhost:3000/health

## 📋 Prerequisites

**Only Docker Required:**
- 🐳 **Docker 20.10+** and **Docker Compose 2.0+**
- 🌐 Network access to your Wazuh Manager
- 💾 500MB RAM and 1GB disk space

**No other dependencies needed** - everything runs inside the container!

## 🛠️ Advanced Configuration

### Manual Configuration
If you prefer not to use the interactive script:

1. **Create environment file**:
```bash
cp config/wazuh.env.example .env.wazuh
```

2. **Edit `.env.wazuh`** with your settings:
```bash
# === REQUIRED SETTINGS ===
WAZUH_HOST=your-wazuh-manager.domain.com
WAZUH_USER=your-api-username
WAZUH_PASS=your-api-password

# === OPTIONAL SETTINGS ===
WAZUH_PORT=55000
MCP_PORT=3000
MCP_TRANSPORT=http
VERIFY_SSL=true
```

3. **Deploy**:
```bash
docker compose up -d
```

### Environment Variables
You can override any setting using environment variables:

```bash
# Quick deploy with environment variables
WAZUH_HOST=wazuh.company.com \
WAZUH_USER=mcp-user \
WAZUH_PASS=secure-password \
docker compose up -d
```

## 🔧 Container Management

### Essential Commands
```bash
# View real-time logs
docker compose logs -f

# Check container status
docker compose ps

# Stop the server
docker compose down

# Restart the server
docker compose restart

# Update to latest version
git pull
docker compose up -d --build
```

### Health & Testing
```bash
# Health check
curl http://localhost:3000/health

# Run functionality tests inside container
docker compose exec wazuh-mcp-server python3 test-functionality.py

# Run production validation
docker compose exec wazuh-mcp-server python3 validate-production.py --quick

# Interactive shell access
docker compose exec wazuh-mcp-server bash
```

## 🌍 Cross-Platform Deployment

### Windows (PowerShell)
```powershell
# Clone and deploy
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
.\configure-wazuh.sh  # Run in WSL/Git Bash
# OR manually create .env.wazuh file
docker compose up -d
```

### macOS/Linux
```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
./configure-wazuh.sh
# Server automatically starts after configuration
```

### Cloud Deployment (AWS/Azure/GCP)
```bash
# On any cloud VM with Docker
curl -fsSL https://get.docker.com | sh
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
./configure-wazuh.sh
# Configure firewall for port 3000 if needed
```

## 🔄 Transport Modes

### HTTP/SSE Mode (Default)
**Best for web clients, remote access, and production use.**
```bash
# Runs on http://localhost:3000
docker compose up -d
```

### STDIO Mode  
**For Claude Desktop direct integration.**
```bash
# Run in STDIO mode
echo "MCP_TRANSPORT=stdio" >> .env.wazuh
docker compose up -d

# Or override with environment variable
MCP_TRANSPORT=stdio docker compose up -d
```

## 📊 Container Specifications

**Base Image**: `python:3.12-slim`
**Size**: ~150MB (compressed)
**Architecture**: Multi-arch (amd64, arm64)
**User**: Non-root (`wazuh` user)
**Security**: Minimal attack surface, no sudo

**Included Dependencies**:
- ✅ FastMCP 2.10.6
- ✅ All Python requirements
- ✅ Validation and test tools
- ✅ Security scanner (tini)
- ✅ Health check endpoint

## 🚨 Troubleshooting

### Common Issues

**Container won't start:**
```bash
# Check logs
docker compose logs

# Verify configuration
docker compose config

# Test Wazuh connectivity
docker compose exec wazuh-mcp-server curl -k https://YOUR_WAZUH_HOST:55000
```

**Cannot connect to Wazuh:**
```bash
# Check network connectivity
docker compose exec wazuh-mcp-server ping your-wazuh-host

# Verify SSL settings
docker compose exec wazuh-mcp-server python3 -c "
from src.wazuh_mcp_server.config import WazuhConfig
config = WazuhConfig.from_env()
print(f'Host: {config.wazuh_host}:{config.wazuh_port}')
print(f'SSL: {config.verify_ssl}')
"
```

**Port already in use:**
```bash
# Use different port
echo "MCP_PORT=3001" >> .env.wazuh
docker compose up -d
```

**Permission denied:**
```bash
# Fix file permissions
chmod +x configure-wazuh.sh
sudo chown -R $USER:$USER .
```

## 🔒 Security Best Practices

### Production Deployment
1. **Use SSL/TLS**: Set `VERIFY_SSL=true`
2. **Secure passwords**: Use strong Wazuh API credentials
3. **Network security**: Restrict access to port 3000
4. **Regular updates**: Keep container updated
5. **Monitor logs**: Use `docker compose logs -f`

### Environment File Security
```bash
# Secure the configuration file
chmod 600 .env.wazuh
```

## 📈 Scaling & Performance

### Resource Limits
Current limits in `compose.yml`:
- **Memory**: 512MB
- **CPU**: 0.5 cores

Adjust as needed:
```yaml
deploy:
  resources:
    limits:
      memory: 1G
      cpus: '1.0'
```

### Multiple Instances
```bash
# Run multiple instances with different ports
MCP_PORT=3001 docker compose up -d --project-name wazuh-mcp-1
MCP_PORT=3002 docker compose up -d --project-name wazuh-mcp-2
```

## 📞 Support

**If you encounter issues:**
1. Check the logs: `docker compose logs -f`
2. Verify Wazuh connectivity
3. Run health checks
4. Review the troubleshooting section above

**Complete OS-agnostic deployment achieved!** 🎉
Everything runs inside Docker with no external dependencies required.