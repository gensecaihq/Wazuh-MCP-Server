# Wazuh MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Wazuh 4.5+](https://img.shields.io/badge/Wazuh-4.5+-orange.svg)](https://wazuh.com/)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://www.docker.com/)
[![Production Ready](https://img.shields.io/badge/Production-Ready-green.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server/releases)

Production-grade Model Context Protocol (MCP) server connecting Wazuh SIEM with Claude Desktop for AI-powered security operations.

## 🚀 Quick Start

```bash
# 1. Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# 2. Configure Wazuh API
cp .env.production .env
vim .env  # Add WAZUH_API_URL, USERNAME, PASSWORD

# 3. Deploy with Docker
./scripts/deploy-production.sh

# 4. Verify
curl -k https://localhost:8443/health
```

## 🎯 Features

### Core Security Tools (26 Total)
- **Alert Management**: Query, analyze, and respond to security alerts
- **Agent Monitoring**: Track agent health, processes, and connections
- **Vulnerability Assessment**: Identify and prioritize security vulnerabilities
- **Compliance Checking**: CIS, PCI-DSS, HIPAA compliance analysis
- **Threat Intelligence**: IOC checking and threat analysis
- **Cluster Management**: Monitor Wazuh cluster health

### Production Architecture
- **Single Container**: Minimal resource usage (256MB RAM)
- **Auto-Configuration**: Zero manual setup required
- **Backward Compatible**: Preserves all v2.0.0 functionality
- **Security Hardened**: OAuth 2.0, JWT tokens, non-root execution

## 📋 Requirements

### Docker Deployment (Recommended)
- Docker 20.10+
- Docker Compose 2.0+
- 1GB free disk space

### Manual Installation
- Python 3.9+
- Wazuh 4.5+ with API access
- 512MB RAM minimum

## 🔧 Installation

### Option 1: Docker (Production)
```bash
# Using deployment script
./scripts/deploy-production.sh

# Or using docker-compose directly
docker-compose up -d
```

### Option 2: Manual Installation
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # or `venv\Scripts\activate` on Windows

# Install dependencies
pip install -r requirements-prod.txt

# Run server
python -m wazuh_mcp_server.main
```

## ⚙️ Configuration

### Required Settings
```bash
# .env file
WAZUH_API_URL=https://your-wazuh:55000
WAZUH_API_USERNAME=your-api-user
WAZUH_API_PASSWORD=your-api-password
```

### Optional Settings
```bash
# Server Configuration
MCP_SERVER_MODE=auto      # auto|stdio|remote
MCP_SERVER_PORT=8443      # HTTPS port

# Security
OAUTH_ENABLED=true        # OAuth 2.0 authentication
JWT_SECRET_KEY=           # Auto-generated if blank

# Performance
MAX_CONNECTIONS=1000      # Concurrent connections
WORKER_PROCESSES=4        # CPU workers
```

## 🔌 Claude Desktop Integration

### Configure Claude Desktop
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["exec", "-i", "wazuh-mcp-server", 
               "python", "-m", "wazuh_mcp_server.main", "--stdio"]
    }
  }
}
```

### Example Usage
```
You: Show me critical alerts from the last hour
Claude: I'll search for critical alerts from the last hour...

You: Analyze security posture of web servers
Claude: Let me analyze the security posture of your web servers...

You: Check if any agents are disconnected
Claude: I'll check the status of all Wazuh agents...
```

## 🛡️ Security

- **Container Security**: Non-root user, read-only filesystem
- **Network Security**: HTTPS only, isolated Docker network
- **Authentication**: OAuth 2.0 with JWT tokens
- **Audit Logging**: JSON structured logs
- **Input Validation**: All endpoints validated

## 📊 Available Tools

<details>
<summary>Click to see all 26 tools</summary>

### Alert Tools
- `get_wazuh_alerts` - Query security alerts
- `get_wazuh_alert_summary` - Alert statistics
- `analyze_wazuh_threats` - AI threat analysis

### Agent Tools
- `check_wazuh_agent_health` - Agent status
- `get_wazuh_agent_processes` - Running processes
- `get_wazuh_agent_ports` - Network connections
- `get_wazuh_running_agents` - Active agents

### Vulnerability Tools
- `get_wazuh_vulnerability_summary` - Vulnerability overview
- `get_wazuh_critical_vulnerabilities` - Critical CVEs

### Compliance Tools
- `check_wazuh_compliance` - Compliance status
- `get_wazuh_risk_assessment` - Risk analysis

### Statistics Tools
- `get_wazuh_weekly_stats` - Weekly statistics
- `get_wazuh_remoted_stats` - Remote statistics
- `get_wazuh_log_collector_stats` - Log collection stats

### Cluster Tools
- `get_wazuh_cluster_health` - Cluster status
- `get_wazuh_cluster_nodes` - Node information
- `search_wazuh_manager_logs` - Log search

### Additional Tools
- `check_wazuh_ioc` - IOC checking
- `get_wazuh_rules_summary` - Rule statistics
- `get_wazuh_manager_error_logs` - Error logs

</details>

## 🚨 Troubleshooting

### Container Won't Start
```bash
# Check logs
docker-compose logs

# Verify credentials
cat .env | grep WAZUH_API

# Test API connection
curl -u user:pass https://wazuh:55000/security/user/authenticate
```

### Health Check Fails
```bash
# Check internal health
docker exec wazuh-mcp-server curl -k https://localhost:8443/health

# Check container status
docker ps
```

### Performance Issues
```bash
# Monitor resources
docker stats

# Increase limits in docker-compose.yml
# Restart: docker-compose up -d
```

## 📚 Documentation

- [Production Deployment Guide](PRODUCTION_README.md)
- [API Documentation](docs/API.md)
- [Security Guide](docs/security/README.md)
- [Troubleshooting](docs/troubleshooting/)

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](docs/development/CONTRIBUTING.md).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file.

## 🔗 Links

- **GitHub**: https://github.com/gensecaihq/Wazuh-MCP-Server
- **Issues**: https://github.com/gensecaihq/Wazuh-MCP-Server/issues
- **Wazuh**: https://wazuh.com/
- **MCP**: https://modelcontextprotocol.io/

---

**Built with ❤️ for the Security Community**