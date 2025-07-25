# Docker Usage Guide - Wazuh MCP Server

## 🚀 Quick Start with Docker

### Prerequisites
- Docker 20.10+ installed
- Docker Compose Plugin 2.0+ installed
- Access to your Wazuh server

### 1-Minute Setup

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Configure your Wazuh settings
cp .env.docker.template .env
# Edit .env with your actual Wazuh server details:
# WAZUH_HOST=your-wazuh-server.com
# WAZUH_USER=your-api-user
# WAZUH_PASS=your-password

# Start the server
docker compose up -d

# Check status
docker compose ps
```

That's it! Your Wazuh MCP Server is running.

---

## 🔧 Configuration Options

### Transport Modes

**STDIO Mode (for Claude Desktop):**
```bash
# Default mode - no additional config needed
docker compose up -d
```

**HTTP/SSE Mode (for remote access):**
```bash
# Set transport mode to HTTP
echo "MCP_TRANSPORT=http" >> .env
docker compose up -d

# Server will be available at http://localhost:3000
```

### Environment Variables

Edit your `.env` file with these settings:

```bash
# Required Wazuh Configuration
WAZUH_HOST=your-wazuh-server.com
WAZUH_PORT=55000
WAZUH_USER=your-api-user
WAZUH_PASS=your-secure-password

# Transport Mode
MCP_TRANSPORT=stdio  # or 'http' for remote access
MCP_HOST=0.0.0.0     # For HTTP mode
MCP_PORT=3000        # For HTTP mode

# Security
VERIFY_SSL=true      # Enable SSL verification

# Optional: External APIs
VIRUSTOTAL_API_KEY=your-key  # For enhanced threat intel
```

---

## 📱 Claude Desktop Integration

### Using Docker with Claude Desktop

**Option 1: Docker Exec (Recommended)**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server", "./wazuh-mcp-server", "--stdio"]
    }
  }
}
```

**Option 2: Direct Container Access**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["container", "run", "--rm", "-i", "--env-file", ".env", "wazuh-mcp-server:v3-fastmcp-check", "--stdio"]
    }
  }
}
```

---

## 🌐 Remote Access (HTTP/SSE)

### Setup for Remote Access

1. **Configure HTTP Transport:**
```bash
# Set environment variables
export MCP_TRANSPORT=http
export MCP_HOST=0.0.0.0
export MCP_PORT=3000

# Start server
docker compose up -d
```

2. **Access the Server:**
- HTTP endpoint: `http://your-server:3000`
- Supports HTTP POST requests and Server-Sent Events
- Compatible with MCP clients that support HTTP transport

3. **Security for Remote Access:**
```bash
# Use environment variables for production
export WAZUH_HOST=your-secure-wazuh-server.com
export VERIFY_SSL=true
export MCP_HOST=0.0.0.0  # Allow external connections
```

---

## 🔧 Docker Commands

### Basic Operations

```bash
# Start server
docker compose up --detach

# Stop server
docker compose down

# Restart server
docker compose restart

# View logs (live)
docker compose logs --follow

# View logs (last 100 lines)  
docker compose logs --tail=100

# Check server status
docker compose ps

# List all containers (including stopped)
docker compose ps --all

# Execute commands inside container
docker compose exec wazuh-mcp-server bash

# Run one-off commands
docker compose run --rm wazuh-mcp-server python3 --version
```

### Troubleshooting

```bash
# Check container health
docker compose ps
docker container inspect wazuh-mcp-server --format='{{.State.Health.Status}}'

# View detailed logs
docker compose logs wazuh-mcp-server

# View logs with timestamps
docker compose logs --timestamps wazuh-mcp-server

# Rebuild container after code changes
docker compose build --no-cache
docker compose up --detach

# Clean rebuild
docker compose down
docker compose build --no-cache
docker compose up --detach

# Remove and recreate everything
docker compose down --volumes --remove-orphans
docker compose up --detach
```

### Development

```bash
# Build custom image (modern buildx)
docker buildx build -t wazuh-mcp-server:custom .

# Build with multiple platforms
docker buildx build --platform linux/amd64,linux/arm64 -t wazuh-mcp-server:custom .

# Run with custom image
docker container run --interactive --tty --env-file .env wazuh-mcp-server:custom --stdio

# Interactive debugging
docker compose exec wazuh-mcp-server bash

# Run with specific configuration
docker compose --profile development up --detach
```

---

## 📊 Monitoring & Health Checks

### Built-in Health Checks

The container includes automatic health checks:

```bash
# Check health status
docker compose ps

# View health check logs
docker container inspect wazuh-mcp-server --format='{{.State.Health}}'
```

### Manual Health Verification

```bash
# Quick validation inside container
docker compose exec wazuh-mcp-server python3 validate-production.py --quick

# Full validation
docker compose exec wazuh-mcp-server python3 validate-production.py

# Test Wazuh connectivity
docker compose exec wazuh-mcp-server python3 -c "
import os
import sys
sys.path.insert(0, 'src')
from wazuh_mcp_server.config import WazuhConfig
config = WazuhConfig.from_env()
print(f'Wazuh server: {config.host}:{config.port}')
"
```

---

## 🔒 Security Best Practices

### Production Deployment

1. **Use Strong Credentials:**
```bash
# Generate secure password
openssl rand -base64 32

# Use dedicated API user (not admin)
WAZUH_USER=mcp-api-user
```

2. **Enable SSL Verification:**
```bash
VERIFY_SSL=true
```

3. **Limit Resources:**
```yaml
# In compose.yml
deploy:
  resources:
    limits:
      memory: 512M
      cpus: '0.5'
```

4. **Network Security:**
```bash
# For HTTP mode, consider reverse proxy
# Use HTTPS with proper certificates
# Implement authentication if needed
```

---

## 🚨 Troubleshooting

### Common Issues

**Container Won't Start:**
```bash
# Check logs
docker compose logs wazuh-mcp-server

# Verify environment variables
docker compose config

# Check file permissions
ls -la docker/entrypoint.sh  # Should be executable
```

**Wazuh Connection Issues:**
```bash
# Test from container
docker compose exec wazuh-mcp-server curl -k https://$WAZUH_HOST:$WAZUH_PORT/

# Check DNS resolution
docker compose exec wazuh-mcp-server nslookup $WAZUH_HOST
```

**Claude Desktop Integration:**
```bash
# Verify container is running
docker compose ps

# Test STDIO mode manually
docker container exec --interactive wazuh-mcp-server ./wazuh-mcp-server --stdio

# Check Claude Desktop logs for connection errors
```

### Getting Help

1. **Enable Debug Logging:**
```bash
echo "LOG_LEVEL=DEBUG" >> .env
docker compose restart
docker compose logs -f
```

2. **Export Configuration:**
```bash
# Check current configuration
docker compose config

# Validate environment
docker compose exec wazuh-mcp-server env | grep WAZUH
```

3. **Report Issues:**
- Include `docker compose logs` output
- Include your sanitized `.env` file
- Specify Docker and Docker Compose versions

---

## 📈 Performance Tuning

### Resource Optimization

```bash
# Adjust memory limits in compose.yml
deploy:
  resources:
    limits:
      memory: 1G      # Increase for high-volume environments
      cpus: '1.0'     # Increase for better performance

# Environment tuning
MAX_ALERTS_PER_QUERY=2000     # Increase for fewer API calls
REQUEST_TIMEOUT_SECONDS=60    # Increase for slow networks
MAX_CONNECTIONS=20            # Increase for high concurrency
```

### Monitoring

```bash
# Monitor resource usage
docker container stats wazuh-mcp-server

# Monitor logs in real-time
docker compose logs --follow --tail=0 wazuh-mcp-server

# Performance metrics (if enabled)
docker compose exec wazuh-mcp-server curl -s http://localhost:3000/metrics
```

---

**Your Wazuh MCP Server is ready! 🎉**

For support, visit: https://github.com/gensecaihq/Wazuh-MCP-Server/issues