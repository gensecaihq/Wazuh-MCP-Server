# 🚀 Production Deployment Guide

## Quick Deploy

### Prerequisites
Ensure Docker is installed on your system. If not, use our automated installation scripts:

**🐧 Linux:** [Install Docker for Linux](README.md#step-1-install-docker-automated---recommended)
**🍎 macOS:** [Install Docker for macOS](README.md#step-1-install-docker-automated---recommended)  
**🪟 Windows:** [Install Docker for Windows](README.md#step-1-install-docker-automated---recommended)

For detailed Docker installation, see [DOCKER_INSTALLATION_GUIDE.md](DOCKER_INSTALLATION_GUIDE.md).

### Deploy

```bash
# 1. Verify Docker installation
./scripts/verify-installation.sh

# 2. Configure credentials
export WAZUH_HOST=wazuh-manager.local
export WAZUH_USER=wazuh-api
export WAZUH_PASS=SecureApiPassword123

# 3. Deploy container
docker compose up -d

# 4. Verify deployment
docker compose ps
python3 test-functionality.py
```

## Architecture

**Production-Ready Container:**
- 🐳 Multi-stage Docker build with security hardening
- 🔒 Non-root execution with dedicated user (wazuh:1000)
- 📊 Resource limits: 512MB memory, 0.5 CPU cores
- 🏥 Health checks with 30s intervals, 3 retries
- ⚡ Async FastMCP server with 21 tools + 2 resources

## Available Capabilities

### Core Security Tools
- `get_wazuh_alerts` - Real-time security alerts
- `search_wazuh_logs` - Advanced log search
- `execute_active_response` - Automated threat response
- `get_security_incidents` - Incident management
- `create_security_incident` - SOC workflow tracking
- `get_wazuh_rules` - Detection rule management
- `get_fim_events` - File integrity monitoring
- `get_cdb_lists` - Threat intelligence lists
- `get_enhanced_analytics` - Predictive security analytics
- `analyze_security_threats` - AI-powered threat analysis
- `get_realtime_alerts` - Live monitoring dashboards
- `advanced_wazuh_query` - Complex multi-field queries
- `get_agent_status` - Agent health monitoring
- `get_vulnerability_summary` - Vulnerability assessment
- `get_cluster_status` - Infrastructure monitoring

### Live Resources
- `wazuh://status/server` - Real-time server status
- `wazuh://dashboard/summary` - Security metrics dashboard

## Configuration

### Required Environment Variables
```bash
WAZUH_HOST=wazuh-manager.local    # Wazuh server
WAZUH_USER=api-user             # API username  
WAZUH_PASS=secure-password      # API password
```

### Optional Settings
```bash
WAZUH_PORT=55000               # API port (default: 55000)
VERIFY_SSL=true               # SSL verification (default: true)
```

### Transport Mode Configuration

You can select transport mode using **three methods** (in order of precedence):

#### 1. Command-Line Arguments (Highest Priority)
```bash
# Available options:
docker compose run --rm wazuh-mcp-server ./wazuh-mcp-server --stdio     # STDIO mode
docker compose run --rm wazuh-mcp-server ./wazuh-mcp-server --local     # STDIO mode (alias)
docker compose run --rm wazuh-mcp-server ./wazuh-mcp-server --http      # HTTP/SSE mode
docker compose run --rm wazuh-mcp-server ./wazuh-mcp-server --remote    # HTTP/SSE mode (alias)
docker compose run --rm wazuh-mcp-server ./wazuh-mcp-server --server    # HTTP/SSE mode (alias)
```

#### 2. Environment Variables (Recommended for Production)
```bash
export MCP_TRANSPORT=stdio     # STDIO mode (default, for Claude Desktop)
export MCP_TRANSPORT=http      # HTTP/SSE mode (for remote access)
export MCP_PORT=3000          # HTTP port (default: 3000, http mode only)
export MCP_HOST=0.0.0.0       # HTTP host (default: 0.0.0.0, http mode only)
```

#### 3. Default Behavior
- Defaults to **STDIO mode** if no arguments or environment variables are set
- Perfect for Claude Desktop integration without additional configuration

## MCP Client Integration

### Claude Desktop (STDIO Mode)

**Option 1: Docker Container Integration**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "wazuh-mcp-server", "./wazuh-mcp-server", "--stdio"]
    }
  }
}
```

**Option 2: Docker with Environment Variables**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "wazuh-mcp-server", "./wazuh-mcp-server"],
      "env": {
        "MCP_TRANSPORT": "stdio"
      }
    }
  }
}
```

**Option 3: Direct Connection (Local Install)**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/wazuh-mcp-server",
      "args": ["--stdio"],
      "env": {
        "WAZUH_HOST": "wazuh-manager.local",
        "WAZUH_USER": "api-user",
        "WAZUH_PASS": "secure-password"
      }
    }
  }
}
```

### Remote Clients (HTTP/SSE Mode)

**Continue.dev, Cursor, Custom MCP Clients:**
```json
{
  "mcpServers": {
    "wazuh": {
      "url": "http://localhost:3000",
      "transport": "http"
    }
  }
}
```

**Production Remote Setup:**
```bash
# Set HTTP mode in production
export MCP_TRANSPORT=http
export MCP_HOST=0.0.0.0
export MCP_PORT=3000
docker compose up -d

# Configure firewall for remote access
sudo ufw allow 3000/tcp
```

## Monitoring & Health

### Container Health
```bash
# Status check
docker compose ps

# Health logs  
docker compose logs wazuh-mcp-server

# Resource usage
docker stats wazuh-mcp-server
```

### Application Testing
```bash
# Full functionality test
python3 test-functionality.py

# Production validation
python3 validate-production.py --quick
```

## Troubleshooting

### Docker Installation Issues

**Docker Not Found or Not Working:**
- Use our automated installation scripts (see Prerequisites above)
- For manual installation: [DOCKER_INSTALLATION_GUIDE.md](DOCKER_INSTALLATION_GUIDE.md)
- Run verification: `./scripts/verify-installation.sh`

**Platform-Specific Docker Issues:**
- **Linux**: Check user permissions: `sudo usermod -aG docker $USER`
- **macOS**: Ensure Docker Desktop is running and has sufficient resources
- **Windows**: Verify WSL2 backend is properly configured

### Wazuh MCP Server Issues

**Connection Errors:**
```bash
# Test Wazuh connectivity
curl -k "https://${WAZUH_HOST}:${WAZUH_PORT:-55000}"

# Check container network
docker network ls

# Full diagnostic
./scripts/verify-installation.sh
```

**Authentication Issues:**
```bash
# Verify credentials
docker compose exec wazuh-mcp-server printenv | grep WAZUH

# Test API auth manually
curl -k -u "${WAZUH_USER}:${WAZUH_PASS}" \
  "https://${WAZUH_HOST}:${WAZUH_PORT:-55000}/security/user/authenticate"
```

**Container Issues:**
```bash
# Complete verification and diagnostic
./scripts/verify-installation.sh

# Rebuild container
docker compose build --no-cache
docker compose up -d

# View detailed logs
docker compose logs wazuh-mcp-server -f --tail=100

# Check container health
docker compose ps
docker inspect wazuh-mcp-server
```

**Performance Issues:**
```bash
# Check resource usage
docker stats wazuh-mcp-server

# Monitor system resources
docker system df
docker system events
```

## Security Features

- ✅ Non-root container execution
- ✅ Multi-stage build for minimal attack surface  
- ✅ SSL/TLS verification enforced
- ✅ Environment-based credential management
- ✅ Resource limits prevent resource exhaustion
- ✅ Health monitoring for operational visibility

## Performance

**Typical Resource Usage:**
- Memory: 150-300MB (512MB limit)
- CPU: 10-30% (0.5 core limit)
- Network: Optimized connection pooling
- Response Time: <500ms for most queries

## Example Queries

```
"Show critical alerts from last hour"
"Create incident for brute force on server-01"
"Execute firewall-block on compromised agent"  
"Search logs for authentication failures"
"Generate threat landscape analytics"
"What's my overall security posture?"
```