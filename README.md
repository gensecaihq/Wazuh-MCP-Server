# 🛡️ Wazuh MCP Server

Production-grade FastMCP server for Wazuh SIEM integration with AI-powered security analysis.

## 🚀 Quick Start

### 1. Configure
```bash
# Set required environment variables
export WAZUH_HOST=your-wazuh-server.com
export WAZUH_USER=your-api-user
export WAZUH_PASS=your-password

# Or use interactive configuration
python3 configure.py
```

### 2. Deploy
```bash
# Start with Docker
docker compose up -d

# Check status
docker compose ps
docker compose logs wazuh-mcp-server
```

### 3. Test
```bash
# Comprehensive functionality test
python3 test-functionality.py

# Quick validation
python3 deploy-validate.py
```

### 4. Connect MCP Client
For Claude Desktop, add to configuration:
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/wazuh-mcp-server",
      "args": ["--stdio"]
    }
  }
}
```

## 📊 Security Capabilities

### 🛠️ Analysis Tools
- **Alert Analysis** - Real-time security alert retrieval and filtering
- **Threat Analysis** - AI-powered threat categorization with risk scoring
- **Agent Monitoring** - Wazuh agent status and health metrics
- **Vulnerability Assessment** - Security vulnerability analysis
- **Cluster Status** - Infrastructure health monitoring

### 📈 Real-time Resources
- **Server Status** - Live connection and health monitoring
- **Security Dashboard** - Real-time security metrics and alert breakdown

## 🏗️ Architecture

```
User Query → FastMCP Server → Wazuh API → Security Analysis → Structured Response
                    ↓
            Context & Progress Tracking
```

**Key Features:**
- FastMCP-compliant with 6 tools + 2 resources
- Robust Wazuh API integration with authentication
- AI-powered threat analysis and risk assessment
- Production-ready Docker deployment
- Comprehensive error handling and monitoring

## 🔧 Configuration

### Required Environment Variables
```bash
WAZUH_HOST=wazuh.company.com     # Wazuh server hostname/IP
WAZUH_USER=api-user              # Wazuh API username
WAZUH_PASS=secure-password       # Wazuh API password
```

### Optional Settings
```bash
WAZUH_PORT=55000                 # Wazuh API port (default: 55000)
MCP_TRANSPORT=stdio              # Transport mode: stdio/http
MCP_PORT=3000                    # HTTP port (for http transport)
VERIFY_SSL=true                  # SSL verification (default: true)
LOG_LEVEL=INFO                   # Logging level
```

## 🧪 Testing & Validation

```bash
# Full functionality test (recommended)
python3 test-functionality.py

# Deployment validation
python3 deploy-validate.py

# Unit tests
pytest tests/ -v
```

## 🚀 Production Deployment

See [PRODUCTION_DEPLOYMENT.md](PRODUCTION_DEPLOYMENT.md) for comprehensive deployment guide including:
- Production configuration
- Security hardening
- Monitoring and health checks
- Troubleshooting guide

## 💡 Example Usage

Once deployed, users can interact with Wazuh through natural language:

- *"Show me recent critical security alerts"*
- *"Analyze threats from the last 24 hours"*
- *"What's the status of my Wazuh agents?"*
- *"Get vulnerability summary for high-severity issues"*

The MCP server translates these requests into secure Wazuh API calls and provides structured, actionable security insights.

## 🔒 Security Features

- Non-root container execution
- SSL certificate verification
- Secure credential management
- Connection retry and error handling
- Resource limits and health monitoring
- Production-grade authentication

## 📄 License

MIT License - see [LICENSE](LICENSE) file.