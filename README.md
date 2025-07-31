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

**Your MCP server is now running at:** `http://localhost:3000`

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

### Claude Desktop Integration

1. Set STDIO mode:
```bash
echo "MCP_TRANSPORT=stdio" >> config/wazuh.env
docker compose restart
```

2. Add to Claude Desktop config:
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["compose", "exec", "wazuh-mcp-server", "./wazuh-mcp-server", "--stdio"],
      "cwd": "/path/to/Wazuh-MCP-Server"
    }
  }
}
```

### Web/HTTP Integration

Default mode - access at `http://localhost:3000`

```bash
# Already configured for HTTP mode
docker compose up -d
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
| `MCP_TRANSPORT` | `http` | Transport mode (`http` or `stdio`) |
| `MCP_PORT` | `3000` | HTTP server port |
| `VERIFY_SSL` | `true` | SSL certificate verification |

### Transport Modes

#### HTTP Mode (Default)
- Best for web clients and remote access
- Access URL: `http://localhost:3000`
- Port: 3000 (configurable)

#### STDIO Mode  
- Direct integration with Claude Desktop
- No network ports required
- Real-time communication

```bash
# Switch to STDIO mode
echo "MCP_TRANSPORT=stdio" >> config/wazuh.env
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
3. **Verify configuration**: Review `config/wazuh.env`
4. **Test connectivity**: Check network access to Wazuh Manager

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