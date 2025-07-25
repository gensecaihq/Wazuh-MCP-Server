# 🛡️ Wazuh MCP Server

Production-grade FastMCP server for Wazuh SIEM integration with comprehensive security analysis.

## 🚀 Quick Deploy

```bash
# 1. Clone & Configure
git clone <repository>
cd Wazuh-MCP-Server

# 2. Set credentials
export WAZUH_HOST=your-wazuh-server.com
export WAZUH_USER=your-api-user  
export WAZUH_PASS=your-password

# 3. Deploy (works on any OS)
docker compose up -d

# 4. Verify
docker compose logs wazuh-mcp-server
```

## 📊 Features

**21 Security Tools + 2 Real-time Resources**
- **Alert & Threat Analysis** - Real-time alerts with AI-powered threat categorization
- **Incident Management** - Create, track, and manage security incidents  
- **Active Response** - Execute automated response commands on agents
- **Log Search** - Advanced log search with filtering capabilities
- **Rule Management** - Query, analyze, and manage detection rules
- **File Integrity Monitoring** - Monitor critical file changes
- **CDB Lists** - Manage threat intelligence and blacklists
- **Enhanced Analytics** - Performance, trends, and predictive insights
- **Real-time Monitoring** - Live dashboards and alert streaming
- **Agent & Vulnerability Management** - Complete asset visibility

## 🏗️ Architecture

```
Claude/LLM → FastMCP Server → Wazuh API → Security Analysis → Insights
                ↓
        Docker Container (OS Agnostic)
```

**Production Ready:**
- 🐳 **Fully Containerized** - Zero host dependencies
- 🌍 **OS Agnostic** - Linux, macOS, Windows via Docker
- 🔒 **Secure** - Non-root execution, SSL verification
- ⚡ **Fast** - Async operations, connection pooling
- 📈 **Scalable** - Resource limits, health monitoring

## 🔧 Configuration

### Required Variables
```bash
WAZUH_HOST=wazuh.company.com
WAZUH_USER=api-user
WAZUH_PASS=secure-password
```

### Optional Settings
```bash
WAZUH_PORT=55000          # API port
MCP_TRANSPORT=stdio       # stdio|http  
VERIFY_SSL=true          # SSL verification
```

## 💡 Usage Examples

```
"Show me recent critical alerts"
"Create incident for brute force attack on server-01" 
"Execute firewall-block on agent 001"
"Search logs for authentication failures"
"Generate security trends with predictions"
"What's my agent health status?"
```

## 🎯 MCP Client Setup

**Claude Desktop:**
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

## 🔍 Validation

```bash
# Test deployment
python3 test-functionality.py

# Production validation  
python3 validate-production.py
```

## 📚 Documentation

- [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md) - Deployment guide
- [LICENSE](LICENSE) - MIT License