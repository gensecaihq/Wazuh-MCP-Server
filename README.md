# Wazuh MCP Server v2.1.0

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Wazuh Compatible](https://img.shields.io/badge/Wazuh-4.8%2B-orange.svg)](https://wazuh.com/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.10.6+-green.svg)](https://github.com/jlowin/fastmcp)

A **production-ready FastMCP server** that connects Wazuh SIEM with Claude Desktop for AI-powered security operations using **STDIO transport only**.

> **🌐 Remote Server Edition**: Looking for enterprise remote access? Check out [**v3.0.0 Remote Server Edition**](https://github.com/gensecaihq/Wazuh-MCP-Server/tree/mcp-remote) with HTTP/SSE transport, Docker deployment, and JWT authentication.

## ✨ Key Features

- 🔍 **29 Security Tools**: Complete FastMCP tool suite for Wazuh integration
- 🧠 **AI-Powered Analysis**: Threat analysis, risk assessment, and compliance reporting  
- 💬 **Natural Language Queries**: Ask Claude "Show me critical vulnerabilities"
- 📡 **STDIO Only**: Secure local connection to Claude Desktop - no network setup
- ⚡ **Dual API Support**: Intelligent routing between Wazuh Server API and Indexer API
- 🛡️ **Production Ready**: Comprehensive health checks, error handling, and security

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Install in development mode
pip install -e .

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Validate setup
wazuh-mcp-server --check
```

## ⚙️ Configuration

### Required Wazuh Settings

Edit `.env` with your Wazuh server details:

```bash
# Wazuh Server API Configuration
WAZUH_HOST=your-wazuh-server.com
WAZUH_PORT=55000
WAZUH_USER=your-api-username
WAZUH_PASS=your-secure-password

# Wazuh Indexer Configuration (for 4.8.0+)
WAZUH_INDEXER_HOST=your-wazuh-server.com
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=your-indexer-username
WAZUH_INDEXER_PASS=your-indexer-password

# SSL Configuration (Production Ready Defaults)
VERIFY_SSL=true                    # Enable SSL verification
WAZUH_ALLOW_SELF_SIGNED=true      # Allow self-signed certificates
```

### SSL Configuration Options

| Scenario | Configuration | Use Case |
|----------|---------------|----------|
| **Production** | `VERIFY_SSL=true` + `WAZUH_ALLOW_SELF_SIGNED=false` | Valid CA certificates |
| **Self-Signed** | `VERIFY_SSL=true` + `WAZUH_ALLOW_SELF_SIGNED=true` | Self-signed certificates |
| **Development** | `VERIFY_SSL=false` | HTTP-only or invalid certificates |

## 🖥️ Claude Desktop Integration

### Configuration

Add to Claude Desktop config:
- **Windows**: `%APPDATA%\\Claude\\claude_desktop_config.json`
- **macOS/Linux**: `~/.config/claude/claude_desktop_config.json`

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

### Usage Examples

Once configured, you can interact with Wazuh through Claude Desktop:

```
🔍 "Show me all critical security alerts from the last 24 hours"
🚨 "What are the top 5 security threats in my environment?"
🛡️ "Run a PCI-DSS compliance check"
📊 "Generate a weekly security report"
🔧 "Check the health of agent web-server-01"
🌐 "Show me vulnerability summary for the last week"
```

## 📚 Complete Tool Reference

### Alert Management (4 tools)
- `get_wazuh_alerts` - Retrieve security alerts with filtering
- `get_wazuh_alert_summary` - Alert summaries and statistics
- `analyze_alert_patterns` - AI-powered pattern analysis
- `search_security_events` - Advanced security event search

### Agent Management (6 tools)
- `get_wazuh_agents` - Agent information and status
- `get_wazuh_running_agents` - Active agents overview
- `check_agent_health` - Comprehensive agent health validation
- `get_agent_processes` - Running processes per agent
- `get_agent_ports` - Open ports and services per agent
- `get_agent_configuration` - Detailed agent configuration

### Vulnerability Management (3 tools)
- `get_wazuh_vulnerabilities` - Comprehensive vulnerability scanning
- `get_wazuh_critical_vulnerabilities` - Critical vulnerabilities only
- `get_wazuh_vulnerability_summary` - Vulnerability statistics and trends

### Security Analysis (6 tools)
- `analyze_security_threat` - AI-powered threat indicator analysis
- `check_ioc_reputation` - IOC reputation checking against threat feeds
- `perform_risk_assessment` - Comprehensive security risk analysis
- `get_top_security_threats` - Top threats by severity and frequency
- `generate_security_report` - Automated security reporting
- `run_compliance_check` - Multi-framework compliance validation

### System Monitoring (10 tools)
- `get_wazuh_statistics` - Comprehensive system statistics
- `get_wazuh_weekly_stats` - Weekly performance and security trends
- `get_wazuh_cluster_health` - Cluster health and status monitoring
- `get_wazuh_cluster_nodes` - Individual cluster node information
- `get_wazuh_rules_summary` - Rule effectiveness and performance
- `get_wazuh_remoted_stats` - Agent communication statistics
- `get_wazuh_log_collector_stats` - Log collection performance metrics
- `search_wazuh_manager_logs` - Manager log search and analysis
- `get_wazuh_manager_error_logs` - Error log retrieval and analysis
- `validate_wazuh_connection` - Connection validation and diagnostics

## 📖 Documentation

### Complete API Documentation
- **[Alert Management API](docs/api/alerts.md)** - Comprehensive alert management tools
- **[Agent Management API](docs/api/agents.md)** - Agent monitoring and health tools
- **[Vulnerability Management API](docs/api/vulnerabilities.md)** - Vulnerability assessment tools
- **[Security Analysis API](docs/api/security-analysis.md)** - AI-powered security analysis tools
- **[System Monitoring API](docs/api/system-monitoring.md)** - Infrastructure monitoring tools
- **[Compliance & Reporting API](docs/api/compliance-reporting.md)** - Compliance and reporting tools
- **[Log Management API](docs/api/log-management.md)** - Advanced log search and analysis

### Deployment Guides
- **[Installation Guide](docs/installation.md)** - Comprehensive installation instructions
- **[Configuration Guide](docs/configuration.md)** - Detailed configuration options
- **[Troubleshooting Guide](docs/troubleshooting.md)** - Common issues and solutions
- **[Security Guide](docs/security.md)** - Security best practices and hardening

## 🔧 Command Line Interface

```bash
# Start the MCP server (default)
wazuh-mcp-server

# Validate configuration and connectivity
wazuh-mcp-server --check

# Show version information
wazuh-mcp-server --version

# Show help information
wazuh-mcp-server --help
```

## 🏗️ Architecture

```
┌─────────────────┐    STDIO    ┌─────────────────┐    HTTPS   ┌─────────────────┐
│                 │◄──────────► │                 │◄─────────► │                 │
│  Claude Desktop │             │ Wazuh MCP Server│            │   Wazuh SIEM    │
│                 │             │                 │            │                 │
└─────────────────┘             └─────────────────┘            └─────────────────┘
                                         │                              │
                                         │                              │
                                         ▼                              ▼
                                ┌─────────────────┐            ┌─────────────────┐
                                │                 │            │                 │
                                │ FastMCP Runtime │            │ Wazuh Indexer   │
                                │ (29 Tools)      │            │ (OpenSearch)    │
                                │                 │            │                 │
                                └─────────────────┘            └─────────────────┘
```

## 🛡️ Security Features

- **🔐 Secure by Default**: SSL/TLS verification enabled by default
- **🚫 No Network Exposure**: STDIO transport only - no HTTP server
- **🔑 Credential Validation**: Strong password requirements and validation
- **📝 Audit Logging**: Comprehensive security event logging
- **⚡ Rate Limiting**: Built-in API rate limiting and connection pooling
- **🛠️ Error Handling**: Graceful error handling and recovery mechanisms

## 🧪 Testing & Validation

```bash
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/

# Run security validation
wazuh-mcp-server --check

# Test Claude Desktop integration
# (Configure Claude Desktop and test with natural language queries)
```

## 📊 System Requirements

### Minimum Requirements
- **OS**: Windows 10+, macOS 10.15+, Linux (any modern distribution)
- **Python**: 3.11 or higher
- **RAM**: 512MB available memory
- **Network**: HTTPS access to Wazuh server

### Recommended Requirements
- **Python**: 3.12 or higher  
- **RAM**: 2GB available memory
- **SSL**: Valid SSL certificates for production use
- **Monitoring**: Centralized logging and monitoring setup

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

- **Documentation**: [Complete documentation](docs/)
- **Issues**: [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)

## 🏆 Production Ready

This software has been designed for **enterprise production use** with:

- ✅ Comprehensive error handling and recovery
- ✅ Production-grade logging and monitoring
- ✅ Security hardening and validation
- ✅ Cross-platform compatibility
- ✅ Extensive documentation and support
- ✅ Full test coverage and validation

## 🚀 **Other Editions**

### **Wazuh MCP Remote Server v3.0.0**

For enterprise deployments requiring remote access, check out our **Remote Server Edition**:

- **🌐 Remote Access**: HTTP/SSE transport for cloud and distributed environments
- **🔐 JWT Authentication**: Enterprise-grade Bearer token authentication
- **🐳 Docker Native**: Multi-platform container deployment
- **📊 Full Monitoring**: Prometheus metrics, health checks, and observability
- **⚡ High Availability**: Circuit breakers, retry logic, and load balancing ready
- **🏢 Enterprise Ready**: Perfect for corporate and cloud deployments

**[→ View Remote Server Edition](https://github.com/gensecaihq/Wazuh-MCP-Server/tree/mcp-remote)**

### **Comparison**

| Feature | v2.1.0 (STDIO) | v3.0.0 (Remote) |
|---------|----------------|-----------------|
| **Transport** | STDIO (local) | HTTP/SSE (remote) |
| **Deployment** | Source install | Docker containers |
| **Authentication** | Local integration | JWT Bearer tokens |
| **Best For** | Direct Claude Desktop | Enterprise/Cloud |

---

**Made with ❤️ for the cybersecurity community**
