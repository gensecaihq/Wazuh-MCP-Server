# Wazuh MCP Server - Production Ready

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.10.6+-green.svg)](https://github.com/anthropics/fastmcp)
[![Wazuh Compatible](https://img.shields.io/badge/Wazuh-4.8%2B-orange.svg)](https://wazuh.com/)
[![Production Ready](https://img.shields.io/badge/status-production%20ready-brightgreen.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server)

A **single, robust, production-ready MCP server** built with FastMCP framework that provides AI-powered security operations through Wazuh SIEM integration. This is a clean, unified implementation focused on production deployment.

## ✨ Key Features

- **🔍 AI-Powered Security**: Advanced threat analysis using Claude models
- **🛡️ Production-Ready**: Comprehensive error handling, logging, and monitoring
- **⚡ FastMCP Framework**: Built on the latest FastMCP 2.10.6+ for enhanced performance
- **🔐 Security-First**: Input validation, rate limiting, and security audit trails
- **📊 Real-Time Monitoring**: Health checks, metrics collection, and alerting
- **🎯 Comprehensive Tools**: Complete Wazuh SIEM integration suite

<img width="797" height="568" alt="claude0mcp-wazuh" src="https://github.com/user-attachments/assets/458d3c94-e1f9-4143-a1a4-85cb629287d4" />

---

## 🚀 Quick Start

### 1. Validate System

```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
python3 validate-production.py
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment

```bash
cp .env.production .env
# Edit .env with your Wazuh credentials
```

### 4. Test Server

```bash
./wazuh-mcp-server
```

### 5. Connect to Claude Desktop

Add to your Claude Desktop config:

**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
**macOS/Linux**: `~/.config/claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python3",
      "args": ["/full/path/to/Wazuh-MCP-Server/wazuh-mcp-server"]
    }
  }
}
```

### 6. Restart Claude Desktop

Start asking Claude about your Wazuh security data with AI-powered insights!

---

## 🏗️ **Production Architecture**

### ✅ **Core Features**
- **FastMCP Framework**: Built on FastMCP 2.10.6+ for enhanced performance
- **Production-Grade**: Comprehensive error handling, logging, and monitoring
- **Security-First**: Input validation, rate limiting, and audit trails
- **AI-Powered**: Advanced threat analysis using Claude models
- **Real-Time Monitoring**: Health checks and performance metrics

### 🔧 **Technical Stack**
- **Framework**: FastMCP 2.10.6+ with HTTP/2 support
- **Transport**: STDIO (standard MCP protocol)
- **Platform**: Cross-platform Python 3.10+
- **Dependencies**: Minimal, production-optimized
- **Architecture**: Single unified server implementation

### 🛡️ **Security & Reliability**
- **Error Handling**: Graceful degradation with retry logic
- **Rate Limiting**: API abuse prevention with burst protection
- **Structured Logging**: JSON-formatted logs with security audit trails
- **Health Monitoring**: Real-time system diagnostics and alerting
- **Memory Management**: Efficient resource utilization

---

## 🛠️ Available Tools

### 🚨 **Core Security Tools**
- **`get_wazuh_alerts`** - Retrieve and enrich alerts with risk scoring
- **`analyze_security_threats`** - AI-powered threat analysis with Claude models
- **`check_wazuh_agent_health`** - Comprehensive agent monitoring and diagnostics
- **`get_server_health`** - Real-time server health and performance metrics

### 📊 **Resources & Data**
- **Cluster Status** (`wazuh://cluster/status`) - Real-time cluster information
- **Security Overview** (`wazuh://security/overview`) - Comprehensive security posture

### 📝 **AI Prompts**
- **Security Briefing** - Generate executive security briefings
- **Incident Investigation** - Structured incident response workflows

### 🎯 **Production Features**
- **Rate Limiting** - API abuse prevention
- **Health Monitoring** - System diagnostics and alerting  
- **Error Recovery** - Graceful failure handling with retries
- **Performance Metrics** - Request tracking and optimization
- **Security Audit** - Comprehensive logging and monitoring

---

## 📋 Requirements

### System Requirements
- **Python**: 3.10 or higher (FastMCP requirement)
- **Memory**: 512MB minimum, 1GB recommended
- **Storage**: 200MB for installation
- **Network**: HTTPS access to Wazuh Manager (port 55000)

### Core Dependencies
```bash
# FastMCP framework (requires Python 3.10+)
fastmcp>=2.10.6

# HTTP client with HTTP/2 support  
httpx[http2]>=0.27.0

# MCP protocol support
mcp>=1.10.1

# Data validation and utilities
pydantic>=1.10.0,<3.0.0
python-dateutil>=2.8.2
python-dotenv>=0.19.0

# Security and SSL
pyjwt>=2.8.0
certifi>=2021.0.0

# System monitoring
packaging>=21.0
psutil>=5.9.0
```

---

## 🔧 Installation Options

### Production Installation (Recommended)
```bash
# 1. Validate system readiness
python3 validate-production.py

# 2. Install all dependencies
pip install -r requirements.txt

# 3. Configure environment
cp .env.production .env
```

### Platform-Specific Scripts
```bash
# Universal installer
python3 scripts/install.py

# Platform-specific installers available:
# - scripts/install_windows.bat (Windows)
# - scripts/install_macos.sh (macOS) 
# - scripts/install_debian.sh (Ubuntu/Debian)
# - scripts/install_fedora.sh (Fedora/RHEL/CentOS)
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
# Ensure Python 3.10+ (FastMCP requirement)
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

### Core Files
- **`server.py`** - Main FastMCP server implementation (single file)
- **`requirements.txt`** - Production dependencies 
- **`wazuh-mcp-server`** - Executable entry point
- **`validate-production.py`** - System validation script

### Setup Guides
- [Configuration Examples](examples/configuration_examples/)
- [Troubleshooting Guides](docs/troubleshooting/)

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

### Current: Single Production-Ready Server ✅
- Unified FastMCP 2.10.6+ server implementation
- Clean, single-file architecture (server.py)
- Production-grade error handling and monitoring
- AI-powered threat analysis with Claude models
- Minimal dependencies, maximum reliability

### Future Enhancements
- Enhanced AI analysis capabilities
- Additional Wazuh API integrations  
- Advanced compliance reporting
- Extended monitoring and alerting
- Performance optimizations

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