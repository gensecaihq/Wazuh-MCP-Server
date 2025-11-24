# Wazuh MCP Server - User Installation Guide

Welcome! This guide will help you install and configure the Wazuh MCP Server for Claude Desktop integration. Choose between two implementation options based on your needs.

## 🎯 Quick Selection Guide

| Feature | STDIO Version (v2.x) | Remote Version (v3.x) |
|---------|---------------------|---------------------|
| **Transport** | Local STDIO | Remote HTTP/SSE |
| **Setup Complexity** | Simple | Moderate |
| **Network Required** | No | Yes |
| **Claude Integration** | Direct local | Remote server |
| **Security** | Local only | JWT authentication |
| **Deployment** | Single command | Docker/Container |
| **Use Case** | Personal/Local | Team/Enterprise |

## 🔧 STDIO Version (Recommended for Most Users)

The STDIO version provides the simplest setup for local Claude Desktop integration.

### Prerequisites
- **Python 3.9+** (3.11+ recommended)
- **Claude Desktop** installed
- **Wazuh Server** with API access

### Installation

#### Method 1: Package Installation (Recommended)
```bash
# Install from PyPI
pip install wazuh-mcp-server

# Verify installation
wazuh-mcp-server --version
```

#### Method 2: Development Installation
```bash
# Clone repository and switch to main branch
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
git checkout main

# Install in development mode
pip install -e .
```

### Configuration

1. **Create Environment File**
   ```bash
   # Copy example configuration
   cp .env.example .env
   ```

2. **Edit Configuration**
   ```bash
   # Edit .env with your settings
   nano .env
   ```

   **Required Settings:**
   ```env
   # Wazuh Server Configuration
   WAZUH_HOST=your-wazuh-server.com
   WAZUH_PORT=55000
   WAZUH_USER=your-api-username
   WAZUH_PASS=your-secure-password
   
   # Wazuh Indexer (for 4.8.0+)
   WAZUH_INDEXER_HOST=your-wazuh-server.com
   WAZUH_INDEXER_PORT=9200
   WAZUH_INDEXER_USER=your-indexer-username
   WAZUH_INDEXER_PASS=your-indexer-password
   
   # SSL Configuration
   VERIFY_SSL=true
   WAZUH_ALLOW_SELF_SIGNED=true
   ```

3. **Validate Configuration**
   ```bash
   wazuh-mcp-server --check
   ```

### Claude Desktop Integration

1. **Locate Configuration File**
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
   - **macOS**: `~/.config/claude/claude_desktop_config.json`
   - **Linux**: `~/.config/claude/claude_desktop_config.json`

2. **Add MCP Server Configuration**
   ```json
   {
     "mcpServers": {
       "wazuh": {
         "command": "wazuh-mcp-server",
         "args": []
       }
     }
   }
   ```

3. **Restart Claude Desktop**

4. **Test Integration**
   Open Claude Desktop and try:
   ```
   "Show me critical security alerts from the last 24 hours"
   ```

## 🌐 Remote Version (Enterprise/Team Use)

The remote version provides a network-accessible MCP server with enterprise features.

### Prerequisites
- **Docker 20.10+** with Compose v2.20+
- **Wazuh Server** with API access
- **Network connectivity** to Wazuh server
- **Domain/IP** for remote access (optional)

### Installation

1. **Clone Repository**
   ```bash
   git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
   cd Wazuh-MCP-Server
   git checkout mcp-remote
   ```

2. **Configure Environment**
   ```bash
   # Copy environment template
   cp .env.example .env
   
   # Edit configuration
   nano .env
   ```

   **Essential Configuration:**
   ```env
   # Wazuh Server Connection
   WAZUH_HOST=https://your-wazuh-server.com
   WAZUH_USER=your-api-user
   WAZUH_PASS=your-api-password
   WAZUH_PORT=55000
   
   # MCP Remote Server
   MCP_HOST=0.0.0.0
   MCP_PORT=3000
   
   # Authentication (Generate secure key)
   AUTH_SECRET_KEY=your-256-bit-secret-key
   
   # CORS for Claude Desktop
   ALLOWED_ORIGINS=https://claude.ai,https://*.anthropic.com
   
   # SSL Configuration
   WAZUH_VERIFY_SSL=false  # Set true for production
   ```

3. **Deploy with Docker**
   
   **Quick Deployment:**
   ```bash
   # Production deployment
   ./deploy-production.sh
   ```
   
   **Manual Deployment:**
   ```bash
   # Start services
   docker compose up -d --build --wait
   
   # Verify deployment
   docker compose ps
   curl http://localhost:3000/health
   ```

### Authentication Setup

1. **Get API Key from Logs**
   ```bash
   # Find generated API key
   docker compose logs wazuh-mcp-remote-server | grep "API key"
   
   # Example output:
   # Created default API key: wazuh_abc123...
   ```

2. **Generate JWT Token**
   ```bash
   # Exchange API key for JWT token
   curl -X POST http://localhost:3000/auth/token \
     -H "Content-Type: application/json" \
     -d '{"api_key": "wazuh_your-generated-api-key"}'
   
   # Save the access_token from response
   ```

3. **Test MCP Endpoint**
   ```bash
   # Test SSE endpoint
   curl -H "Authorization: Bearer your-jwt-token" \
        -H "Origin: http://localhost" \
        -H "Accept: text/event-stream" \
        http://localhost:3000/sse
   ```

### Claude Desktop Integration

1. **Configure Claude Desktop**
   
   **For Local Development:**
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
   
   **For Production Deployment:**
   ```json
   {
     "mcpServers": {
       "wazuh-remote": {
         "url": "https://your-domain.com/sse",
         "headers": {
           "Authorization": "Bearer your-jwt-token-here"
         }
       }
     }
   }
   ```

2. **Restart Claude Desktop**

3. **Test Integration**
   ```
   "Show me Wazuh cluster health status"
   ```

## ⚙️ Configuration Options

### SSL/TLS Configuration

| Scenario | VERIFY_SSL | WAZUH_ALLOW_SELF_SIGNED | Use Case |
|----------|------------|------------------------|----------|
| **Production** | `true` | `false` | Valid CA certificates |
| **Self-Signed** | `true` | `true` | Self-signed certificates |
| **Development** | `false` | `false` | HTTP-only or testing |

### Environment Variables Reference

| Variable | STDIO | Remote | Description | Default |
|----------|-------|--------|-------------|---------|
| `WAZUH_HOST` | ✅ | ✅ | Wazuh server URL | Required |
| `WAZUH_PORT` | ✅ | ✅ | Wazuh API port | `55000` |
| `WAZUH_USER` | ✅ | ✅ | API username | Required |
| `WAZUH_PASS` | ✅ | ✅ | API password | Required |
| `WAZUH_INDEXER_HOST` | ✅ | ✅ | Indexer URL | Same as WAZUH_HOST |
| `WAZUH_INDEXER_PORT` | ✅ | ✅ | Indexer port | `9200` |
| `WAZUH_INDEXER_USER` | ✅ | ✅ | Indexer username | Same as WAZUH_USER |
| `WAZUH_INDEXER_PASS` | ✅ | ✅ | Indexer password | Same as WAZUH_PASS |
| `VERIFY_SSL` | ✅ | ✅ | SSL verification | `true` |
| `WAZUH_ALLOW_SELF_SIGNED` | ✅ | ✅ | Allow self-signed certs | `true` |
| `MCP_HOST` | ❌ | ✅ | Server bind address | `127.0.0.1` |
| `MCP_PORT` | ❌ | ✅ | Server port | `3000` |
| `AUTH_SECRET_KEY` | ❌ | ✅ | JWT signing key | Required |
| `LOG_LEVEL` | ✅ | ✅ | Logging verbosity | `INFO` |
| `ALLOWED_ORIGINS` | ❌ | ✅ | CORS origins | Claude domains |

## 🛠️ Available Tools

Both versions provide the same 29 security tools:

### Alert Management (4 tools)
- `get_wazuh_alerts` - Retrieve and filter security alerts
- `get_wazuh_alert_summary` - Alert statistics and summaries
- `analyze_alert_patterns` - AI-powered pattern analysis
- `search_security_events` - Advanced event search

### Agent Management (6 tools)
- `get_wazuh_agents` - Agent information and status
- `get_wazuh_running_agents` - Active agent monitoring
- `check_agent_health` - Comprehensive health checks
- `get_agent_processes` - Process inventory per agent
- `get_agent_ports` - Network port monitoring
- `get_agent_configuration` - Agent configuration details

### Vulnerability Management (3 tools)
- `get_wazuh_vulnerabilities` - Vulnerability assessments
- `get_wazuh_critical_vulnerabilities` - Critical vulnerabilities
- `get_wazuh_vulnerability_summary` - Vulnerability statistics

### Security Analysis (6 tools)
- `analyze_security_threat` - AI threat analysis
- `check_ioc_reputation` - IOC reputation checks
- `perform_risk_assessment` - Risk analysis
- `get_top_security_threats` - Top threat identification
- `generate_security_report` - Automated reporting
- `run_compliance_check` - Compliance validation

### System Monitoring (10 tools)
- `get_wazuh_statistics` - System metrics
- `get_wazuh_weekly_stats` - Weekly trends
- `get_wazuh_cluster_health` - Cluster monitoring
- `get_wazuh_cluster_nodes` - Node information
- `get_wazuh_rules_summary` - Rule effectiveness
- `get_wazuh_remoted_stats` - Communication stats
- `get_wazuh_log_collector_stats` - Collection metrics
- `search_wazuh_manager_logs` - Log search
- `get_wazuh_manager_error_logs` - Error analysis
- `validate_wazuh_connection` - Connection testing

## 🧪 Testing Your Installation

### STDIO Version Testing
```bash
# Test configuration
wazuh-mcp-server --check

# Test Claude integration
# Open Claude Desktop and ask:
# "Show me the current Wazuh cluster status"
```

### Remote Version Testing
```bash
# Check service health
curl http://localhost:3000/health

# Test authentication
curl -X POST http://localhost:3000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "your-api-key"}'

# Test SSE endpoint
curl -H "Authorization: Bearer your-token" \
     -H "Accept: text/event-stream" \
     http://localhost:3000/sse
```

## 🚨 Troubleshooting

### Common Issues

#### STDIO Version Issues

**"Command not found: wazuh-mcp-server"**
```bash
# Ensure pip installation path is in PATH
pip show wazuh-mcp-server
# If installed, add pip's bin directory to PATH
```

**"Connection failed to Wazuh server"**
```bash
# Test direct connection
curl -u "username:password" https://your-wazuh:55000/

# Check SSL settings
echo "VERIFY_SSL=false" >> .env
wazuh-mcp-server --check
```

**"Claude Desktop can't find MCP server"**
```bash
# Check if command works in terminal
wazuh-mcp-server --help

# Verify Claude Desktop config file location
# Restart Claude Desktop after config changes
```

#### Remote Version Issues

**"Container fails to start"**
```bash
# Check logs
docker compose logs wazuh-mcp-remote-server

# Check port availability
netstat -ln | grep 3000

# Rebuild containers
docker compose down && docker compose up --build -d
```

**"Authentication failed"**
```bash
# Generate new API key
docker compose restart wazuh-mcp-remote-server
docker compose logs | grep "API key"

# Test token generation
curl -X POST http://localhost:3000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "new-api-key"}'
```

**"Claude Desktop connection refused"**
```bash
# Test endpoint accessibility
curl http://localhost:3000/health

# Check CORS configuration
grep ALLOWED_ORIGINS .env

# Verify token is valid
curl -H "Authorization: Bearer token" http://localhost:3000/sse
```

### Getting Help

1. **Check Logs**
   - STDIO: Enable debug logging with `LOG_LEVEL=DEBUG`
   - Remote: `docker compose logs -f wazuh-mcp-remote-server`

2. **Validate Configuration**
   - STDIO: `wazuh-mcp-server --check`
   - Remote: `curl http://localhost:3000/health`

3. **Community Support**
   - GitHub Issues: Report bugs and get help
   - GitHub Discussions: Community questions
   - Documentation: Check README.md for your branch

## 📈 System Requirements

### Minimum Requirements
- **OS**: Windows 10+, macOS 10.15+, Linux (modern)
- **Python**: 3.9+ (STDIO) / Docker (Remote)
- **RAM**: 512MB available
- **Network**: HTTPS access to Wazuh server

### Recommended Requirements
- **Python**: 3.11+ (better performance)
- **RAM**: 2GB+ available
- **SSL**: Valid certificates for production
- **Monitoring**: Centralized logging

## 🎉 Success Examples

After successful installation, you can ask Claude Desktop:

```
🔍 "Show me all critical security alerts from today"
🚨 "What are the top 5 threats in my environment?"  
🛡️ "Run a PCI-DSS compliance check"
📊 "Generate a weekly security summary"
🔧 "Check the health of agent web-server-01"
🌐 "Show me vulnerability statistics for the last week"
🏥 "What's the current Wazuh cluster status?"
📈 "Show me agent connectivity statistics"
```

---

**Congratulations! Your Wazuh MCP Server is now ready for AI-powered security operations with Claude Desktop.**

For questions or issues, please check the [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues) or [Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions).