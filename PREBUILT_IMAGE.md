# 🚀 Pre-Built Docker Image Usage

**Skip the build process entirely! Use our pre-built, production-ready Docker image.**

## 📦 Available Images

```bash
# Latest stable version
ghcr.io/gensecaihq/wazuh-mcp-server:latest

# Specific version
ghcr.io/gensecaihq/wazuh-mcp-server:2.0.0
```

**Supported Platforms:**
- ✅ `linux/amd64` (Intel/AMD 64-bit)
- ✅ `linux/arm64` (Apple Silicon, ARM servers)

## ⚡ Quick Deploy with Pre-Built Image

### One-Command Deploy
```bash
docker run -d \
  --name wazuh-mcp-server \
  --restart unless-stopped \
  -p 3000:3000 \
  -e WAZUH_HOST=your-wazuh-host.com \
  -e WAZUH_USER=your-api-username \
  -e WAZUH_PASS=your-api-password \
  ghcr.io/gensecaihq/wazuh-mcp-server:latest
```

### Using Docker Compose (Recommended)

1. **Create compose.yml:**
```yaml
name: wazuh-mcp-server

services:
  wazuh-mcp-server:
    image: ghcr.io/gensecaihq/wazuh-mcp-server:latest
    container_name: wazuh-mcp-server
    restart: unless-stopped
    init: true
    
    environment:
      # Required Wazuh settings
      WAZUH_HOST: your-wazuh-host.com
      WAZUH_USER: your-api-username
      WAZUH_PASS: your-api-password
      
      # Optional settings (defaults shown)
      WAZUH_PORT: 55000
      MCP_TRANSPORT: http
      MCP_HOST: 0.0.0.0
      MCP_PORT: 3000
      VERIFY_SSL: true
    
    ports:
      - "3000:3000"
    
    healthcheck:
      test: ["CMD", "python3", "-c", "from src.wazuh_mcp_server.config import WazuhConfig; WazuhConfig.from_env()"]
      interval: 30s
      timeout: 10s
      retries: 3
    
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
```

2. **Deploy:**
```bash
docker compose up -d
```

3. **Access:**
```
🌐 Server: http://localhost:3000
🏥 Health: http://localhost:3000/health
```

## 🔧 Configuration Options

### Environment Variables
```bash
# Required
WAZUH_HOST=your-wazuh-manager.domain.com
WAZUH_USER=your-api-username
WAZUH_PASS=your-api-password

# Optional
WAZUH_PORT=55000              # Wazuh API port
MCP_PORT=3000                # Server port
MCP_TRANSPORT=http           # http or stdio
VERIFY_SSL=true              # SSL verification
LOG_LEVEL=INFO               # Logging level
ENVIRONMENT=production       # Environment type
```

### Volume Mounts (Optional)
```bash
docker run -d \
  -v ./logs:/app/logs \
  -v ./config:/app/config \
  -e WAZUH_HOST=your-host \
  # ... other options
  ghcr.io/gensecaihq/wazuh-mcp-server:latest
```

## 🛠️ Management Commands

### Container Management
```bash
# Check status
docker ps | grep wazuh-mcp-server

# View logs
docker logs -f wazuh-mcp-server

# Restart container
docker restart wazuh-mcp-server

# Stop container
docker stop wazuh-mcp-server

# Remove container
docker rm wazuh-mcp-server
```

### Health & Testing
```bash
# Health check
curl http://localhost:3000/health

# Run tests inside container
docker exec wazuh-mcp-server python3 test-functionality.py

# Production validation
docker exec wazuh-mcp-server python3 validate-production.py --quick

# Interactive shell
docker exec -it wazuh-mcp-server bash
```

## 🔄 Transport Modes

### HTTP/SSE Mode (Default)
```bash
# Default mode - best for web clients
docker run -d -p 3000:3000 \
  -e WAZUH_HOST=your-host \
  -e WAZUH_USER=user \
  -e WAZUH_PASS=pass \
  ghcr.io/gensecaihq/wazuh-mcp-server:latest

# Access: http://localhost:3000
```

### STDIO Mode
```bash
# For Claude Desktop integration
docker run -d \
  -e MCP_TRANSPORT=stdio \
  -e WAZUH_HOST=your-host \
  -e WAZUH_USER=user \
  -e WAZUH_PASS=pass \
  ghcr.io/gensecaihq/wazuh-mcp-server:latest
```

## 🌍 Multi-Platform Usage

### Intel/AMD Systems
```bash
docker run --platform linux/amd64 \
  -d -p 3000:3000 \
  -e WAZUH_HOST=your-host \
  ghcr.io/gensecaihq/wazuh-mcp-server:latest
```

### ARM Systems (Apple Silicon, ARM servers)
```bash
docker run --platform linux/arm64 \
  -d -p 3000:3000 \
  -e WAZUH_HOST=your-host \
  ghcr.io/gensecaihq/wazuh-mcp-server:latest
```

## 🔒 Security Best Practices

### Production Deployment
```bash
# Use secrets for sensitive data
echo "your-password" | docker secret create wazuh-pass -

# Run with limited resources
docker run -d \
  --memory=512m \
  --cpus=0.5 \
  --read-only \
  --tmpfs /tmp \
  -p 3000:3000 \
  -e WAZUH_HOST=your-host \
  -e WAZUH_USER=user \
  -e WAZUH_PASS=your-pass \
  ghcr.io/gensecaihq/wazuh-mcp-server:latest
```

### Network Security
```bash
# Create dedicated network
docker network create wazuh-net

# Run in isolated network
docker run -d \
  --network wazuh-net \
  -p 127.0.0.1:3000:3000 \
  -e WAZUH_HOST=your-host \
  ghcr.io/gensecaihq/wazuh-mcp-server:latest
```

## 📊 Image Information

### Image Details
- **Base**: Python 3.12 slim
- **Size**: ~150MB compressed
- **User**: Non-root (`wazuh:1000`)
- **Dependencies**: All included
- **Architecture**: Multi-platform (amd64, arm64)

### Included Components
- ✅ FastMCP 2.10.6
- ✅ All Python dependencies
- ✅ Validation tools
- ✅ Health monitoring
- ✅ Security hardening

## 🚨 Troubleshooting

### Image Pull Issues
```bash
# Force pull latest
docker pull ghcr.io/gensecaihq/wazuh-mcp-server:latest

# Check available tags
docker search gensecaihq/wazuh-mcp-server
```

### Container Issues
```bash
# Check container logs
docker logs wazuh-mcp-server

# Test connectivity
docker exec wazuh-mcp-server curl -k https://your-wazuh-host:55000

# Validate configuration
docker exec wazuh-mcp-server python3 -c "
from src.wazuh_mcp_server.config import WazuhConfig
config = WazuhConfig.from_env()
print(f'Wazuh: {config.wazuh_host}:{config.wazuh_port}')
"
```

## 🎯 Advantages of Pre-Built Image

- ✅ **No Build Time** - Instant deployment
- ✅ **Consistent Environment** - Same image everywhere
- ✅ **Multi-Platform** - Works on Intel and ARM
- ✅ **Production Tested** - Fully validated
- ✅ **Optimized Size** - Minimal footprint
- ✅ **Security Hardened** - Non-root, minimal attack surface

## 🔄 Updates

### Update to Latest Version
```bash
# Pull latest image
docker pull ghcr.io/gensecaihq/wazuh-mcp-server:latest

# Recreate container
docker compose down
docker compose up -d
```

---

**🐳 Ready-to-Deploy Docker Image - Zero Build Required!**

*Just pull the image and run with your Wazuh credentials.*