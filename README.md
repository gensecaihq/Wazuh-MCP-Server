# 🛡️ Wazuh MCP Server

FastMCP-powered Model Context Protocol server for Wazuh SIEM integration.

## 🚀 Quick Deployment

### 1. Configure
```bash
python3 configure.py
```

### 2. Deploy
```bash
docker compose up -d
```

### 3. Validate
```bash
python3 deploy-validate.py
```

## 🔧 Configuration

### Environment Variables
```bash
# Required
WAZUH_HOST=your-wazuh-server.com
WAZUH_USER=your-api-user
WAZUH_PASS=your-password

# Optional
MCP_TRANSPORT=stdio  # or 'http'
VERIFY_SSL=true
LOG_LEVEL=INFO
```

### Claude Desktop Setup
```json
{
  "mcpServers": {
    "wazuh-security": {
      "command": "/path/to/wazuh-mcp-server",
      "args": ["--stdio"]
    }
  }
}
```

## 📊 Available Tools & Resources

### 🛠️ Security Analysis Tools
- **`get_wazuh_alerts`** - Real-time alert analysis with filtering
- **`analyze_security_threats`** - AI-powered threat categorization and risk scoring
- **`get_agent_status`** - Agent monitoring with health metrics
- **`get_vulnerability_summary`** - Vulnerability assessment with severity breakdown
- **`get_cluster_status`** - Cluster health and node monitoring

### 📊 Real-time Resources
- **`wazuh://status/server`** - Live server connection status
- **`wazuh://dashboard/summary`** - Security dashboard with alert breakdown

## 🏗️ Architecture

```
FastMCP Server → Wazuh Manager API → Security Data
      ↓
Claude Desktop (STDIO) / Remote HTTP Access
```

## 🧪 Testing

```bash
# Comprehensive functionality test
python3 test-functionality.py

# Quick deployment validation
python3 deploy-validate.py

# Unit tests
pytest tests/ -v
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file.