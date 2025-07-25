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

## 📊 Available Tools

- **`get_wazuh_alerts`** - Real-time alert analysis
- **`analyze_security_threats`** - Threat categorization  
- **`get_agent_status`** - Agent monitoring
- **`get_vulnerability_summary`** - Vulnerability assessment
- **`interactive_threat_hunt`** - Guided threat hunting
- **`get_cluster_status`** - Cluster health monitoring

## 🏗️ Architecture

```
FastMCP Server → Wazuh Manager API → Security Data
      ↓
Claude Desktop (STDIO) / Remote HTTP Access
```

## 🧪 Testing

```bash
pytest tests/ -v
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file.