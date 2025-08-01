# 🛡️ Wazuh MCP Server

**Production-ready FastMCP server for Wazuh SIEM integration with comprehensive security analysis capabilities.**

> 🐳 **Docker-Only Deployment** - Zero OS dependencies. Just install Docker and deploy anywhere.

## 🚀 Quick Start

### Prerequisites
- Docker 20.10+ and Docker Compose 2.0+
- Network access to your Wazuh Manager
- Valid Wazuh API credentials

### 1-Minute Deployment

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Configure your Wazuh connection
./configure-wazuh.sh

# Deploy immediately
docker compose up -d
```

**Your MCP server is now configured and running.**
**Mode:** Local (STDIO) by default, or Remote (HTTP/SSE) if chosen

## ⚙️ Configuration

You only need to set **3 required variables**:

```bash
export WAZUH_HOST=your-wazuh-manager.company.com
export WAZUH_USER=your-api-username  
export WAZUH_PASS=your-api-password
```

### Quick Configuration Script

```bash
./configure-wazuh.sh
```

This interactive script will:
- Prompt for your Wazuh server details
- Create the configuration file
- Validate the connection
- Start the MCP server

### Manual Configuration

Edit `config/wazuh.env`:
```bash
WAZUH_HOST=wazuh-manager.your-domain.com
WAZUH_USER=mcp-user
WAZUH_PASS=secure-password
```

## 🔌 Client Integration

### Claude Desktop Direct Integration (Recommended)

**Default mode** - Standard MCP over STDIO/JSON:

The configuration script automatically sets up direct Claude Desktop integration. Add this to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["compose", "exec", "wazuh-mcp-server", "./wazuh-mcp-server", "--stdio"],
      "cwd": "/absolute/path/to/Wazuh-MCP-Server"
    }
  }
}
```

### Claude Desktop Custom Connector (Advanced)

For remote deployments, choose "Remote Mode" during configuration:

1. **Get your bearer token:**
   ```bash
   grep MCP_AUTH_TOKEN .env.wazuh | cut -d'=' -f2
   ```

2. **Add Custom Connector in Claude Desktop:**
   - Go to Settings > Connectors
   - Click "Add Custom Connector" 
   - Server URL: `http://localhost:3000` (or your custom URL)
   - Authentication: Bearer Token
   - Token: [Your token from step 1]

### Legacy FastMCP Mode

For FastMCP compatibility:
```bash
echo "MCP_TRANSPORT=http" >> .env.wazuh
docker compose restart
```

## 🛠️ Available Tools

The MCP server provides **20 security tools**:

### Core Security Operations
- `get_wazuh_alerts` - Retrieve and analyze security alerts
- `search_wazuh_logs` - Advanced log search and filtering
- `get_agent_status` - Monitor agent health and connectivity
- `get_vulnerability_summary` - Comprehensive vulnerability assessment
- `analyze_security_threats` - AI-powered threat analysis

### Advanced Operations
- `get_realtime_alerts` - Live security monitoring
- `execute_active_response` - Automated threat response
- `multi_field_search` - Cross-source security investigations
- `get_security_incidents` - Incident management
- `get_enhanced_analytics` - Predictive security analytics

### Real-time Resources
- `wazuh://status/server` - Live server health monitoring
- `wazuh://dashboard/summary` - Security metrics dashboard

## 🌐 Production Deployment

### Reverse Proxy Setup

For production deployment without showing ports, use a reverse proxy:

#### Nginx Configuration Example
```nginx
server {
    listen 443 ssl http2;
    server_name wazuh.company.com;
    
    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # Required for SSE
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 24h;
    }
}
```

#### Custom Path Configuration
```bash
# For URLs like https://server.com/wazuhsse
export MCP_PUBLIC_URL=https://server.com/wazuhsse  
export MCP_BASE_PATH=/wazuhsse
docker compose up -d
```

See [docs/nginx-reverse-proxy.conf](docs/nginx-reverse-proxy.conf) for complete examples.

## 🐳 Container Management

### Essential Commands

```bash
# View logs
docker compose logs -f

# Check status
docker compose ps

# Stop server
docker compose down

# Restart server
docker compose restart

# Update to latest
git pull && docker compose up -d --build
```

### Health Monitoring

```bash
# Health check
curl http://localhost:3000/health

# Container health
docker compose exec wazuh-mcp-server python3 validate-production.py

# Run tests
docker compose exec wazuh-mcp-server python3 test-functionality.py
```

## 🔧 Advanced Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_HOST` | *required* | Wazuh Manager hostname/IP |
| `WAZUH_USER` | *required* | Wazuh API username |
| `WAZUH_PASS` | *required* | Wazuh API password |
| `WAZUH_PORT` | `55000` | Wazuh API port |
| `MCP_TRANSPORT` | `stdio` | Transport mode (`stdio`, `remote`, or `http`) |
| `MCP_PORT` | `3000` | Server port |
| `MCP_AUTH_TOKEN` | *auto-generated* | Bearer token for authentication |
| `VERIFY_SSL` | `true` | SSL certificate verification |

### MCP Server Endpoints

| Endpoint | Description | Authentication |
|----------|-------------|----------------|
| `/` | Server information | None |
| `/health` | Health check | None |
| `/sse` | Server-Sent Events for real-time MCP | Bearer token |
| `/message` | MCP protocol messages | Bearer token |
| `/capabilities` | Server capabilities | Bearer token |
| `/.well-known/oauth-authorization-server` | OAuth metadata | None |

### Production Deployment Options

| Deployment Type | Example URL | Configuration |
|-----------------|-------------|---------------|
| **Domain (no port)** | `https://wazuh.company.com` | `MCP_PUBLIC_URL=https://wazuh.company.com` |
| **IP with path** | `https://192.168.1.100/wazuhsse` | `MCP_PUBLIC_URL=https://192.168.1.100/wazuhsse`<br>`MCP_BASE_PATH=/wazuhsse` |
| **Subdomain + path** | `https://mcp.company.com/api/wazuh` | `MCP_PUBLIC_URL=https://mcp.company.com/api/wazuh`<br>`MCP_BASE_PATH=/api/wazuh` |

### Transport Modes

#### STDIO Mode (Default, Recommended)
- **Best for:** Direct Claude Desktop integration  
- **Authentication:** None (local access)
- **Transport:** Standard input/output (JSON-RPC)
- **Performance:** Best performance and compatibility
- **Setup:** Automatic via configuration script

#### Remote Mode (Advanced)
- **Best for:** Claude Desktop Custom Connectors, production deployments
- **Authentication:** Bearer token required
- **Endpoints:** `/sse`, `/message`, `/capabilities`
- **Compliance:** Full MCP remote server specification
- **Features:** Reverse proxy support, custom domains

#### FastMCP HTTP Mode (Legacy)
- **Best for:** FastMCP-compatible clients
- **Authentication:** None (legacy mode)
- **Access:** `http://localhost:3000`

```bash
# Switch modes manually (or use configure-wazuh.sh)
echo "MCP_TRANSPORT=stdio" >> .env.wazuh   # Default (recommended)
echo "MCP_TRANSPORT=remote" >> .env.wazuh  # Remote server
echo "MCP_TRANSPORT=http" >> .env.wazuh    # Legacy FastMCP
docker compose restart
```

## 🚨 Troubleshooting

### Connection Issues

```bash
# Test Wazuh connectivity
docker compose exec wazuh-mcp-server curl -k https://YOUR_WAZUH_HOST:55000

# Check container logs
docker compose logs wazuh-mcp-server

# Verify configuration
docker compose exec wazuh-mcp-server python3 -c "
from src.wazuh_mcp_server.config import WazuhConfig
config = WazuhConfig.from_env()
print(f'Host: {config.wazuh_host}:{config.wazuh_port}')
"
```

### Common Solutions

**Connection Refused:**
- Verify `WAZUH_HOST` is correct
- Check firewall rules for port 55000
- Ensure Wazuh API is enabled

**Authentication Failed:**
- Verify `WAZUH_USER` and `WAZUH_PASS`
- Check user permissions in Wazuh
- Confirm API access is enabled

**Container Won't Start:**
- Check Docker daemon is running
- Verify port 3000 is available
- Review logs: `docker compose logs`

## 🔒 Security Features

- **Container Security**: Non-root user, minimal attack surface
- **SSL/TLS Support**: Certificate verification enabled by default
- **Rate Limiting**: Built-in API rate limiting
- **Health Monitoring**: Comprehensive health checks
- **Input Validation**: Pydantic validation on all inputs

## 📊 Monitoring & Metrics

### Built-in Monitoring

```bash
# Server health
curl http://localhost:3000/health

# Container metrics
docker stats wazuh-mcp-server

# Application metrics
docker compose exec wazuh-mcp-server python3 -c "
import asyncio
from src.wazuh_mcp_server.server import mcp
asyncio.run(mcp.get_tools())
"
```

### Log Analysis

```bash
# Real-time logs
docker compose logs -f wazuh-mcp-server

# Error logs only
docker compose logs wazuh-mcp-server | grep ERROR

# Last 100 lines
docker compose logs --tail 100 wazuh-mcp-server
```

## 🌍 Multi-Platform Support

Works on any OS with Docker:

- ✅ **Linux** (Ubuntu, CentOS, RHEL, etc.)
- ✅ **macOS** (Intel & Apple Silicon)  
- ✅ **Windows** (Docker Desktop)
- ✅ **Cloud** (AWS, Azure, GCP)
- ✅ **Kubernetes** (with Helm charts)

## 📚 Documentation

- [Quick Start Guide](docs/QUICK_START.md) - Get running in 5 minutes
- [Configuration Guide](docs/guides/CONFIGURATION.md) - Detailed setup options
- [API Reference](docs/API_REFERENCE.md) - Complete tool documentation
- [Troubleshooting](docs/TROUBLESHOOTING.md) - Common issues and solutions

## 🆘 Support

### Getting Help

1. **Check the logs**: `docker compose logs -f`
2. **Run health check**: `curl http://localhost:3000/health`
3. **Test remote MCP server**: `python3 test-remote-mcp.py`
4. **Verify configuration**: Review `.env.wazuh`
5. **Test connectivity**: Check network access to Wazuh Manager

### Reporting Issues

When reporting issues, please include:
- Docker version: `docker --version`
- Container logs: `docker compose logs`
- Configuration: `cat config/wazuh.env` (remove passwords)
- Error messages and steps to reproduce

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**🐳 Zero OS Dependencies - Deploy Anywhere with Docker**

*Professional SIEM integration made simple. From development to production in minutes.*