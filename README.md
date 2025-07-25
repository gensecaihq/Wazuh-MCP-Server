# 🛡️ Wazuh MCP Server

Production-grade FastMCP server for Wazuh SIEM integration with comprehensive security analysis. Connects to Wazuh Manager and Indexer for complete SIEM capabilities.

## 📋 Prerequisites

### Wazuh Infrastructure Requirements

**Wazuh Manager (Required)**
- Wazuh Manager 4.8.0+ with API enabled (tested up to 4.12.0+)
- API authentication credentials (username/password)
- Network connectivity on port 55000 (default)
- Valid SSL certificate (recommended for production)
- REST API v4.8+ features enabled
- Auto SSL negotiation support (4.8+)

**Wazuh Indexer (Recommended for Enhanced Features)**
- Wazuh Indexer 4.8.0+ for advanced search and analytics (4.12+ recommended)
- Network connectivity on port 9200 (default)  
- Authentication credentials if security is enabled
- Enables enhanced analytics, vulnerability data, and performance improvements
- Required for full compliance reporting and advanced threat analysis
- CTI (Cyber Threat Intelligence) integration support (4.12+)

### System Requirements
- Docker 20.10+ and Docker Compose 2.0+
- 512MB RAM minimum, 1GB recommended
- Network access to Wazuh infrastructure
- MCP client (Claude Desktop, Continue, etc.)

## 🚀 Quick Deploy

### Step 1: Clone Repository
```bash
git clone https://github.com/your-org/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
```

### Step 2: Configure Wazuh Connection
```bash
# Required: Wazuh Manager settings
export WAZUH_HOST=your-wazuh-manager.com
export WAZUH_USER=your-api-user
export WAZUH_PASS=your-secure-password

# Optional: Wazuh Manager port (default: 55000)
export WAZUH_PORT=55000

# Recommended: Wazuh Indexer for 4.8+ enhanced capabilities
export WAZUH_INDEXER_HOST=your-wazuh-indexer.com
export WAZUH_INDEXER_PORT=9200
export WAZUH_INDEXER_USER=indexer-user
export WAZUH_INDEXER_PASS=indexer-password

# Enable 4.8+ specific features
export USE_INDEXER_FOR_VULNERABILITIES=true
export ENABLE_CENTRALIZED_VULNERABILITY_DETECTION=true

# Enable 4.12+ enhanced features
export ENABLE_CTI_INTEGRATION=true
export ENABLE_PACKAGE_CONDITION_FIELDS=true
export USE_UTC_TIMESTAMPS=true
```

### Step 3: Choose Transport Mode

**STDIO Mode (Recommended for Claude Desktop):**
```bash
export MCP_TRANSPORT=stdio
docker compose up -d
```

**HTTP/SSE Mode (For Remote Access):**
```bash
export MCP_TRANSPORT=http
export MCP_PORT=3000
docker compose up -d
```

### Step 4: Verify Deployment
```bash
# Check container status
docker compose ps

# View logs
docker compose logs wazuh-mcp-server

# Test functionality
python3 test-functionality.py
```

## 📊 Capabilities

### 🔧 20 Security Tools Available (4.8-4.12+ Compatible)

**Core Security Operations:**
- `get_wazuh_alerts` - Real-time security alerts with filtering
- `search_wazuh_logs` - Advanced log search across all sources
- `get_agent_status` - Agent health and connectivity monitoring
- `get_vulnerability_summary` - Comprehensive vulnerability assessment
- `get_cluster_status` - Wazuh infrastructure health monitoring

**Incident & Response Management:**
- `get_security_incidents` - View and track security incidents
- `create_security_incident` - Create new incident tickets
- `update_security_incident` - Update incident status and details
- `execute_active_response` - Automated threat response actions

**Detection & Analytics:**
- `get_wazuh_rules` - Detection rules management
- `analyze_rule_coverage` - Rule effectiveness analysis
- `get_rule_decoders` - Log parsing decoder management
- `advanced_wazuh_query` - Complex multi-field queries
- `multi_field_search` - Advanced search capabilities
- `get_enhanced_analytics` - Predictive security analytics
- `analyze_security_threats` - AI-powered threat analysis

**Monitoring & Intelligence:**
- `get_realtime_alerts` - Live alert monitoring dashboards
- `get_live_dashboard_data` - Real-time security metrics
- `get_cdb_lists` - Threat intelligence and blacklists
- `get_fim_events` - File integrity monitoring events

### 📡 2 Real-time Resources
- `wazuh://status/server` - Live server status and health
- `wazuh://dashboard/summary` - Security metrics dashboard

## 🏗️ Architecture

```
MCP Client → FastMCP Server → Wazuh Manager API → Security Data
(Claude)         ↓              ↓                    ↓
            Docker Container → Wazuh Indexer → Enhanced Analytics
                               (Optional)
```

**Production Architecture:**
- 🐳 **Containerized Deployment** - Zero host dependencies
- 🌍 **OS Agnostic** - Linux, macOS, Windows via Docker
- 🔒 **Security Hardened** - Non-root execution, SSL verification
- ⚡ **High Performance** - Async operations, connection pooling
- 📈 **Scalable Design** - Resource limits, health monitoring
- 🔄 **Dual Transport** - STDIO for desktop, HTTP/SSE for remote

## ⚙️ Configuration

### Required Environment Variables

**Wazuh Manager Connection:**
```bash
WAZUH_HOST=wazuh-manager.company.com    # Wazuh Manager hostname/IP
WAZUH_USER=mcp-api-user                 # API username with read permissions
WAZUH_PASS=secure-api-password          # API user password
```

### Optional Environment Variables

**Wazuh Manager Settings:**
```bash
WAZUH_PORT=55000                        # Wazuh API port (default: 55000)
VERIFY_SSL=true                        # SSL certificate verification (default: true)
```

**Wazuh Indexer Settings (Required for 4.8+ Full Features):**
```bash
WAZUH_INDEXER_HOST=wazuh-indexer.company.com         # Indexer hostname/IP
WAZUH_INDEXER_PORT=9200                              # Indexer port (default: 9200)
WAZUH_INDEXER_USER=indexer-user                      # Indexer username
WAZUH_INDEXER_PASS=indexer-password                  # Indexer password
USE_INDEXER_FOR_ALERTS=true                          # Enable indexer for alerts
USE_INDEXER_FOR_VULNERABILITIES=true                 # Required for 4.8+ vulnerability detection
ENABLE_CENTRALIZED_VULNERABILITY_DETECTION=true      # Use 4.8+ centralized vulnerability feeds
ENABLE_CTI_INTEGRATION=true                          # Enable 4.12+ CTI threat intelligence
ENABLE_PACKAGE_CONDITION_FIELDS=true                 # Enable 4.12+ enhanced package conditions
USE_UTC_TIMESTAMPS=true                              # Use 4.12+ UTC timestamp format
```

**MCP Transport Configuration:**
```bash
MCP_TRANSPORT=stdio                     # Transport mode: stdio|http
MCP_HOST=0.0.0.0                       # HTTP server host (http mode only)
MCP_PORT=3000                          # HTTP server port (http mode only)
```

**Performance Tuning:**
```bash
MAX_ALERTS_PER_QUERY=1000              # Maximum alerts per request
REQUEST_TIMEOUT_SECONDS=30             # API request timeout
MAX_CONNECTIONS=10                      # Connection pool size
```

### Transport Mode Selection

**STDIO Mode (Recommended for Desktop):**
- Direct integration with Claude Desktop
- Low latency, secure local communication
- Ideal for single-user scenarios

**HTTP/SSE Mode (For Remote Access):**
- Web-based access for remote clients
- Supports multiple concurrent connections
- Ideal for team/server deployments

## 💡 Usage Examples

```
"Show me recent critical alerts"
"Create incident for brute force attack on server-01" 
"Execute firewall-block on agent 001"
"Search logs for authentication failures"
"Generate security trends with predictions"
"What's my agent health status?"
```

## 🎯 MCP Client Integration

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

**Option 2: Direct Binary (After Local Install)**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/wazuh-mcp-server",
      "args": ["--stdio"],
      "env": {
        "WAZUH_HOST": "your-wazuh-server.com",
        "WAZUH_USER": "your-api-user",
        "WAZUH_PASS": "your-password"
      }
    }
  }
}
```

### HTTP/SSE Mode Integration

**Continue.dev, Cursor, or Custom Clients:**
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

### Remote HTTP Access
```bash
# Start in HTTP mode
export MCP_TRANSPORT=http
export MCP_HOST=0.0.0.0
export MCP_PORT=3000
docker compose up -d

# Access from remote client
curl http://your-server:3000/health
```

## 🔍 Testing & Validation

### Quick Deployment Test
```bash
# Basic functionality test
python3 test-functionality.py

# Production readiness validation
python3 validate-production.py --quick

# Full production audit
python3 validate-production.py --full
```

### Manual Testing
```bash
# Test Wazuh connectivity
curl -k "https://${WAZUH_HOST}:${WAZUH_PORT}/security/user/authenticate" \
  -u "${WAZUH_USER}:${WAZUH_PASS}"

# Test MCP server health (HTTP mode)
curl http://localhost:3000/health

# Check container logs
docker compose logs wazuh-mcp-server -f
```

## 🚨 Troubleshooting

### Common Issues

**Connection Errors:**
- Verify Wazuh Manager is accessible on specified port
- Check firewall rules and network connectivity
- Validate SSL certificates if VERIFY_SSL=true

**Authentication Failures:**
- Confirm API user exists in Wazuh Manager
- Verify user has sufficient read permissions
- Check password special characters are properly escaped

**Container Issues:**
```bash
# Rebuild container
docker compose build --no-cache
docker compose up -d

# Check resource usage
docker stats wazuh-mcp-server

# View detailed logs
docker compose logs wazuh-mcp-server --tail=100
```

## 💡 Usage Examples

Once connected to your MCP client, try these commands:

```
"Show me recent critical alerts"
"What's the status of agent 001?"
"Create incident for brute force attack on server-01"
"Execute firewall-block on compromised agent"
"Search logs for authentication failures in last 24 hours"
"Generate security analytics with trend predictions"
"What vulnerabilities exist in my environment?" (uses 4.8+ centralized detection)
"Show me CTI threat intelligence for this CVE" (4.12+ feature)
"Analyze threat landscape with CTI data" (4.12+ enhanced)
"Show me file integrity violations"
"Check for new Wazuh version updates" (4.8+ feature)
"Get detailed vulnerability info with package conditions" (4.12+ feature)
```

## 📚 Documentation

- [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md) - Complete deployment guide
- [LICENSE](LICENSE) - MIT License
- [Contributing Guidelines](.github/CONTRIBUTING.md) - Development setup

## 🤝 Support

- **Issues**: [GitHub Issues](https://github.com/your-org/Wazuh-MCP-Server/issues)
- **Documentation**: [Full Documentation](https://docs.your-org.com/wazuh-mcp-server)
- **Community**: [Discussions](https://github.com/your-org/Wazuh-MCP-Server/discussions)