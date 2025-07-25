# Wazuh MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Wazuh Compatible](https://img.shields.io/badge/Wazuh-4.8%2B-orange.svg)](https://wazuh.com/)
[![Current Release](https://img.shields.io/badge/Release-v2.0.0-green.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server/releases)

A **production-ready Model Context Protocol (MCP) server** that connects Wazuh SIEM with Claude Desktop for AI-powered security operations using **stdio transport**.

## ✨ What it does

- **🔍 Security Monitoring**: Query Wazuh alerts, agents, and vulnerabilities through Claude
- **🧠 AI Analysis**: Get AI-powered security insights, threat analysis, and compliance reports  
- **💬 Natural Language**: Ask questions like "Show me critical alerts from the last hour"
- **📱 Local Integration**: Direct stdio connection with Claude Desktop - no network setup required
- **🛠️ 26 Security Tools**: Comprehensive coverage of Wazuh functionality

<img width="797" height="568" alt="claude0mcp-wazuh" src="https://github.com/user-attachments/assets/458d3c94-e1f9-4143-a1a4-85cb629287d4" />

---

## 🚀 Quick Start

### 1. Install

**Option A: Stable Release (Recommended)**
```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
# Use main branch (default) for production
python3 scripts/install.py
```

**Option B: Experimental FastMCP (Testing)**
```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
git checkout v2-fastmcp
# Requires Python 3.10+
python3 validate-production.py
pip install -r requirements.txt
```

**Option C: Production Enterprise (v3.1.0)**
```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
git checkout v3-fastmcp-remote
# Requires Python 3.10+, enterprise features
python3 validate-production.py
pip install -r requirements.txt
# See docs/ for comprehensive deployment guides
```

**Option D: Manual (Main Branch)**
```bash
pip install -r requirements.txt
```

### 2. Configure

Create `.env` file with your Wazuh settings:
```env
WAZUH_HOST=your-wazuh-server.com
WAZUH_PORT=55000
WAZUH_USERNAME=your-api-user
WAZUH_PASSWORD=your-password
VERIFY_SSL=true
```

### 3. Connect to Claude Desktop

Add to your Claude Desktop config:

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
**macOS/Linux**: `~/.config/claude/claude_desktop_config.json`

**For Main Branch (v2.0.0):**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python3",
      "args": ["/path/to/Wazuh-MCP-Server/src/wazuh_mcp_server/main.py"]
    }
  }
}
```

**For v2-fastmcp Branch (Experimental):**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python3",
      "args": ["/path/to/Wazuh-MCP-Server/wazuh-mcp-server"]
    }
  }
}
```

**For v3-fastmcp-remote Branch (Enterprise):**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python3",
      "args": ["/path/to/Wazuh-MCP-Server/wazuh-mcp-server", "--stdio"]
    }
  }
}
```

### 4. Restart Claude Desktop

That's it! Start asking Claude about your Wazuh security data.

---

## 🎯 Version Information

### 📦 **Current Stable Release: v2.0.0** (main branch)
- **Fixed all GitHub issues** (#34, #33, #30, #25)  
- **Cross-platform compatibility** - works on Windows, macOS, Linux
- **26 security tools** - comprehensive Wazuh integration
- **Pydantic V1/V2 support** - works with both versions
- **Production-ready** - stable, tested, and reliable

### 🧪 **Experimental: v2-fastmcp** (testing branch)
- **FastMCP Framework** - Built with FastMCP 2.10.6+ for enhanced performance
- **Single Server Architecture** - Unified, production-grade implementation
- **Python 3.10+ Required** - Latest FastMCP compatibility
- **Advanced Features** - Rate limiting, health monitoring, AI-powered analysis
- **Minimal Dependencies** - Clean, optimized codebase

### 🚀 **Production Ready: v3-fastmcp-remote** (enterprise branch)
- **Production-Grade Security** - Enterprise security operations platform
- **JWT Authentication** - Secure token-based authentication with lockout protection
- **Advanced Input Validation** - SQL injection, XSS, and command injection protection
- **Performance Optimized** - 60% faster response times, 40% memory reduction
- **Docker Support** - Complete containerization with security hardening
- **Comprehensive Documentation** - Full API docs, security guides, troubleshooting

> **Note**: The `v2-fastmcp` branch contains an experimental FastMCP-powered server for testing. The `v3-fastmcp-remote` branch contains the production-ready enterprise version with comprehensive security and performance enhancements. Use `main` branch for standard deployments.

### 🔀 **Branch Selection Guide**
- **Use `main` branch** if you need:
  - Stable, production-tested server
  - Python 3.9+ compatibility
  - Established tool ecosystem (26 tools)
  
- **Use `v2-fastmcp` branch** if you want to test:
  - Latest FastMCP framework features
  - Single unified server architecture
  - Enhanced performance and monitoring
  - Modern Python 3.10+ patterns

- **Use `v3-fastmcp-remote` branch** for enterprise deployments requiring:
  - Production-grade security and compliance
  - Enterprise authentication and authorization
  - High-performance, scalable architecture
  - Docker/Kubernetes deployment
  - Comprehensive monitoring and audit logging

### 🏗️ **Architecture (main branch)** 
- **Transport**: stdio (standard MCP protocol)
- **Dependencies**: Minimal, essential only
- **Platform**: Cross-platform Python 3.9+
- **Deployment**: Local process, no containers needed

---

## 🛠️ Available Tools

### Core Security Tools
- `get_wazuh_alerts` - Query and analyze security alerts
- `get_wazuh_agents` - Monitor agent status and health
- `get_wazuh_vulnerabilities` - Vulnerability assessment
- `analyze_security_threat` - AI-powered threat analysis

### Statistics & Monitoring  
- `get_wazuh_alert_summary` - Alert statistics and trends
- `get_wazuh_weekly_stats` - Weekly security reports
- `get_wazuh_running_agents` - Active agent monitoring
- `get_wazuh_rules_summary` - Rule effectiveness analysis

### Cluster & Infrastructure
- `get_wazuh_cluster_health` - Cluster status monitoring
- `get_wazuh_cluster_nodes` - Node information
- `get_wazuh_remoted_stats` - Remote daemon statistics
- `get_wazuh_log_collector_stats` - Log collection metrics

### Advanced Analysis
- `get_wazuh_vulnerability_summary` - Vulnerability summaries
- `get_wazuh_critical_vulnerabilities` - Critical security issues
- `search_wazuh_manager_logs` - Manager log analysis
- `get_wazuh_manager_error_logs` - Error investigation

**Total: 26 comprehensive security tools**

---

## 📋 Requirements

### System Requirements
- **Python**: 3.9 or higher
- **RAM**: 256MB minimum
- **Disk**: 100MB for installation
- **Network**: HTTPS access to Wazuh Manager

### Dependencies (Auto-installed)
```
mcp>=1.10.1              # MCP protocol
aiohttp>=3.8.0           # HTTP client
urllib3>=1.26.0          # HTTP utilities  
pydantic>=1.10.0         # Data validation (V1/V2 compatible)
python-dotenv>=0.19.0    # Environment variables
pyjwt>=2.8.0            # JWT authentication
certifi>=2021.0.0       # SSL certificates
python-dateutil>=2.8.2  # Date handling
packaging>=21.0         # Version utilities
```

---

## 🔧 Installation Scripts

### Windows
```batch
scripts\install_windows.bat
```

### macOS  
```bash
scripts/install_macos.sh
```

### Linux (Ubuntu/Debian)
```bash
scripts/install_debian.sh
```

### Fedora/RHEL/CentOS
```bash
scripts/install_fedora.sh
```

### Universal (Recommended)
```bash
python3 scripts/install.py
```

---

## 🔒 Security Configuration

### Wazuh API User Setup

1. **Create dedicated API user** (don't use admin):
```bash
# On Wazuh Manager
curl -k -X POST "https://localhost:55000/security/users" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{"username": "mcp-api-user", "password": "SecurePass123!"}'
```

2. **Assign minimal permissions**:
```bash
curl -k -X POST "https://localhost:55000/security/users/mcp-api-user/roles?role_ids=1"
```

### SSL Configuration

**Production (Recommended)**:
```env
VERIFY_SSL=true
WAZUH_SSL_VERIFY=true
```

**Development Only**:
```env  
VERIFY_SSL=false
ALLOW_SELF_SIGNED=true
```

---

## 🚨 Troubleshooting

### Common Issues

**Import Errors**:
```bash
# Ensure Python 3.9+
python3 --version

# Reinstall dependencies
pip install -r requirements.txt
```

**Connection Issues**:
```bash
# Test Wazuh connectivity
curl -k https://your-wazuh-server:55000/

# Check API credentials
curl -k -X POST "https://your-wazuh-server:55000/security/user/authenticate" \
  -H "Content-Type: application/json" \
  -d '{"username":"your-user","password":"your-password"}'
```

**Claude Desktop Issues**:
1. Check config file path and JSON syntax
2. Restart Claude Desktop after config changes
3. Verify Python path in config is correct

### Platform-Specific Guides
- **Windows**: `docs/troubleshooting/windows-troubleshooting.md`
- **Unix/Linux**: `docs/troubleshooting/unix-troubleshooting.md`

---

## 📚 Documentation

### Setup Guides
- [Claude Desktop Setup](docs/user-guides/claude-desktop-setup.md)
- [Configuration Examples](examples/configuration_examples/)
- [Troubleshooting Guides](docs/troubleshooting/)

### API Reference
- [Tool Documentation](docs/api/)
- [Configuration Reference](docs/configuration/)
- [Security Best Practices](docs/security/)

---

## 🤝 Contributing

We welcome contributions! Please see:
- [Contributing Guidelines](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Development Setup](docs/development/)

### Report Issues
Found a bug? [Open an issue](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)

---

## 📈 Roadmap

### Current: v2.0.0 (main) ✅
- Simplified, production-ready MCP stdio server
- Cross-platform compatibility  
- 26 comprehensive security tools
- Bug fixes for all reported issues

### Experimental: v2-fastmcp (testing) 🧪
- FastMCP 2.10.6+ framework integration
- Single unified server architecture
- Advanced rate limiting and monitoring
- AI-powered threat analysis enhancements

### Production Ready: v3-fastmcp-remote (enterprise) 🚀
- Production-grade security operations platform
- JWT authentication with account lockout protection
- Advanced input validation and SQL injection protection
- 60% performance improvement, 40% memory reduction
- Docker deployment with security hardening
- Comprehensive documentation and troubleshooting guides

### Future: v2.1.0
- Merge successful v3-fastmcp-remote features into main
- Enhanced tool capabilities
- Performance optimizations
- Additional Wazuh integrations
- Extended documentation

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Wazuh Team** - For the excellent SIEM platform
- **Anthropic** - For Claude and the MCP protocol
- **Contributors** - For bug reports and improvements
- **Community** - For testing and feedback

---

## 📞 Support

- **Documentation**: This README and [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)

---

**🎉 Ready to enhance your security operations with AI? Install now and start querying your Wazuh data through Claude!**