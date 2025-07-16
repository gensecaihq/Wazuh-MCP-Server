# Wazuh MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![Wazuh Compatible](https://img.shields.io/badge/Wazuh-4.8%2B-orange.svg)](https://wazuh.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://hub.docker.com/)
[![Production Ready](https://img.shields.io/badge/Production-Ready-green.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server/releases)

A production-grade Model Context Protocol (MCP) server that connects Wazuh SIEM with Claude Desktop and Claude Code for AI-powered security operations.

## What it does

- **Security Monitoring**: Query Wazuh alerts, agents, and vulnerabilities through Claude
- **AI Analysis**: Get AI-powered security insights, threat analysis, and compliance reports
- **Natural Language**: Ask questions like "Show me critical alerts from the last hour" or "Analyze this security incident"
- **Flexible Deployment**: Choose between Docker containerization (v3) or traditional installation (v2)
- **Production Ready**: Full monitoring, high availability, and security hardening

<img width="797" height="568" alt="claude0mcp-wazuh" src="https://github.com/user-attachments/assets/458d3c94-e1f9-4143-a1a4-85cb629287d4" />

## 🏷️ Version Information

### **🐳 v3.0.0 - Docker-First Production** (Current - July 15, 2025)
- **Status**: ✅ **Production Ready** - [GitHub Release](https://github.com/gensecaihq/Wazuh-MCP-Server/releases/tag/v3.0.0)
- **Deployment**: **Docker-only** with complete containerization
- **Transport**: HTTP/SSE for remote access + stdio for development
- **Features**: Remote MCP server, OAuth2 authentication, High Availability
- **Best For**: Production environments requiring remote access and enterprise security
- **Host Requirements**: **Docker only** - no Python/dependency management needed

### **🔧 v2.0.0 - Traditional Installation** 
- **Status**: ✅ **Stable** - [GitHub Release](https://github.com/gensecaihq/Wazuh-MCP-Server/releases/tag/v2.0.0)
- **Deployment**: Traditional Python installation with manual dependency management
- **Transport**: stdio (local only)
- **Features**: 26 security tools with Phase 5 enhancement system
- **Best For**: Local development, testing, and environments without Docker
- **Host Requirements**: Python 3.9+, manual dependency installation

### **🏛️ v1.0.0 - Legacy** 
- **Status**: ✅ **Legacy Support** - [GitHub Release](https://github.com/gensecaihq/Wazuh-MCP-Server/releases/tag/v1.0.0)
- **Features**: 14 core security tools
- **Best For**: Minimal installations and legacy systems

> **💡 Recommendation**: Use **v3.0.0** for all production deployments. Use **v2.0.0** for development environments without Docker.

---

## 🚀 Quick Start

### 🐳 v3.0.0: Production Docker Deployment (Recommended)

**Complete containerized deployment - no host dependencies required:**

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Switch to v3 branch
git checkout v3-check

# Create environment configuration
cp .env.example .env
# Edit .env with your Wazuh details

# Single command deployment
docker compose up -d

# Verify deployment
docker compose ps
curl -f http://localhost:8443/health
```

**✅ What you get with v3 Docker:**
- 🔐 OAuth2 authentication with JWT tokens
- 🌐 Remote MCP access via HTTP/SSE
- 📊 Prometheus + Grafana monitoring stack
- 🔄 High availability with load balancing
- 🛡️ Security hardened containers
- 📋 Automated backups and incident response
- ⚡ Zero host system dependencies

**🎯 Key Advantage**: Host OS becomes irrelevant - works identically on Windows, macOS, and Linux

### 🔧 v2.0.0: Traditional Installation

**For development and non-Docker environments:**

```bash
# Clone and switch to v2
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
git checkout main  # v2 is on main branch

# Install dependencies (requires Python 3.9+)
python3 scripts/install.py

# Configure environment
cp .env.example .env
# Edit .env with your Wazuh details

# Run locally (stdio mode)
python3 -m wazuh_mcp_server.main --stdio
```

---

## 🔧 Configuration

### v3.0.0 Docker Configuration

**Environment file (`.env`):**
```env
# Wazuh Configuration
WAZUH_HOST=your-wazuh-server.com
WAZUH_USER=your-username
WAZUH_PASS=your-password
WAZUH_PORT=55000

# v3 Remote Server Configuration
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8443
MCP_TRANSPORT=sse

# Authentication (v3 Production)
JWT_SECRET_KEY=your-256-bit-secret-key
OAUTH_CLIENT_ID=wazuh-mcp-client
OAUTH_CLIENT_SECRET=secure-client-secret
OAUTH_ENABLED=true

# Security
VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=true

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090
LOG_LEVEL=INFO
```

### v2.0.0 Traditional Configuration

**Same `.env` file format, but simplified:**
```env
# Wazuh Configuration (Required)
WAZUH_HOST=your-wazuh-server.com
WAZUH_USER=your-username
WAZUH_PASS=your-password
WAZUH_PORT=55000

# Security
VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=true

# Logging
LOG_LEVEL=INFO
```

---

## 🔌 Claude Integration

### v3.0.0: Remote MCP (Production)
```json
{
  "mcpServers": {
    "wazuh": {
      "type": "url",
      "url": "https://your-server:8443/sse",
      "name": "wazuh-mcp",
      "authorization": {
        "type": "oauth2",
        "authorization_url": "https://your-server:8443/oauth/authorize",
        "token_url": "https://your-server:8443/oauth/token",
        "client_id": "wazuh-mcp-client",
        "scopes": ["read:alerts", "read:agents", "read:vulnerabilities"]
      }
    }
  }
}
```

### v2.0.0: Local stdio (Development)
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/full/path/to/Wazuh-MCP-Server/scripts/mcp_wrapper.sh",
      "args": ["--stdio"]
    }
  }
}
```

---

## 🎯 Features (Both Versions)

### 🔍 Security Tools (26 Total)
- **get_alerts**: Retrieve and filter Wazuh alerts
- **analyze_threats**: AI-powered threat analysis
- **check_agent_health**: Monitor agent status
- **compliance_check**: Compliance assessments (PCI DSS, GDPR, HIPAA, etc.)
- **risk_assessment**: Comprehensive security risk analysis
- **vulnerability_prioritization**: Risk-based vulnerability management
- And 20 more advanced security tools...

### 🔐 v3.0.0 Additional Enterprise Features
- **OAuth 2.0 Server**: Full authorization server with client management
- **JWT Token Management**: Secure token creation, validation, and revocation
- **Rate Limiting**: Per-client rate limiting with abuse protection
- **SSL/TLS Support**: Full HTTPS with certificate management
- **Audit Logging**: Complete security event logging
- **High Availability**: Load balancing with auto-recovery
- **Monitoring Stack**: Prometheus + Grafana dashboards

---

## 📊 Performance & Requirements

### v3.0.0 Docker Requirements
```bash
# Host Requirements (minimal)
- Docker 20.10+
- Docker Compose 2.0+
- 2GB RAM minimum
- 10GB storage

# Everything else containerized:
- Python 3.12 (in container)
- Redis 7.4 (in container)
- Prometheus 2.55.0 (in container)
- Grafana 11.4.0 (in container)
- HAProxy 3.0 (in container)
- All dependencies (in container)
```

### v2.0.0 Traditional Requirements
```bash
# Host Requirements (manual setup)
- Python 3.9+
- pip/poetry for dependency management
- Platform-specific dependencies
- Manual SSL certificate management
- Manual monitoring setup
```

### Performance Benchmarks
- **Startup Time**: v3: < 10s (includes stack), v2: < 5s
- **Memory Usage**: v3: < 1GB (full stack), v2: < 512MB
- **Response Time**: Both < 200ms (p95)
- **Scaling**: v3: Horizontal scaling, v2: Single instance

---

## 🛠️ Development

### v3.0.0 Development with Docker
```bash
# Development with live reload
docker compose -f docker-compose.dev.yml up -d

# Run tests in container
docker compose exec wazuh-mcp-server pytest

# Access container for debugging
docker compose exec wazuh-mcp-server bash
```

### v2.0.0 Traditional Development
```bash
# Setup virtual environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests
pytest tests/

# Start development server
python3 -m wazuh_mcp_server.main --stdio
```

---

## 🔄 Migration Between Versions

### From v2 to v3 (Recommended)
```bash
# Backup your configuration
cp .env .env.backup

# Switch to v3
git checkout v3-check

# Deploy with Docker (uses same .env)
docker compose up -d
```

### From v3 to v2 (If needed)
```bash
# Switch to v2
git checkout main

# Install dependencies
python3 scripts/install.py

# Use existing .env file
python3 -m wazuh_mcp_server.main --stdio
```

---

## 🧪 Testing

### v3.0.0 Testing
```bash
# Test full Docker stack
docker compose -f docker-compose.test.yml up --abort-on-container-exit

# Individual service tests
docker compose exec wazuh-mcp-server pytest tests/
```

### v2.0.0 Testing
```bash
# Local testing
pytest tests/
pytest --cov=src --cov-report=html
```

---

## 🔧 Troubleshooting

### v3.0.0 Docker Troubleshooting
```bash
# Check all services
docker compose ps

# View logs
docker compose logs -f

# Health checks
curl -f http://localhost:8443/health
docker compose exec wazuh-mcp-server python -c "import wazuh_mcp_server; print('OK')"

# Clean restart
docker compose down -v
docker compose up -d
```

### v2.0.0 Traditional Troubleshooting
```bash
# Test setup
python scripts/validate_setup.py

# Check dependencies
pip check

# Test Wazuh connection
curl -u username:password https://your-wazuh:55000/
```

### Common Issues

#### Authentication Issues
**Both versions**: Wazuh Dashboard and API use separate authentication.

1. **Create API User** in Wazuh Dashboard:
   - Go to **Security** → **Internal users**
   - Create user with `wazuh` backend role
   - Use these credentials in `.env`

2. **Test API Authentication**:
   ```bash
   curl -k -X POST "https://your-wazuh:55000/security/user/authenticate" \
     -H "Content-Type: application/json" \
     -d '{"username":"your-api-user","password":"your-api-password"}'
   ```

---

## 📚 Documentation

### Quick References
- **v3.0.0 Docker Guide**: [docs/v3/README_v3.md](docs/v3/README_v3.md)
- **v2.0.0 Installation Guide**: [docs/user-guides/claude-desktop-setup.md](docs/user-guides/claude-desktop-setup.md)
- **Migration Guide**: [docs/MIGRATION_GUIDE.md](docs/MIGRATION_GUIDE.md)
- **Troubleshooting**: [docs/troubleshooting/](docs/troubleshooting/)

### Operations
- **Production Deployment**: [docs/operations/PRODUCTION_DEPLOYMENT.md](docs/operations/PRODUCTION_DEPLOYMENT.md)
- **High Availability**: [docs/operations/HIGH_AVAILABILITY.md](docs/operations/HIGH_AVAILABILITY.md)
- **Security Guide**: [docs/security/README.md](docs/security/README.md)

---

## 🏆 Version Comparison Summary

| Feature | v2.0.0 (Traditional) | v3.0.0 (Docker) | 
|---------|----------------------|------------------|
| **Deployment** | Manual installation | Single `docker compose up` |
| **Host Dependencies** | Python 3.9+, manual deps | Docker only |
| **Transport** | stdio only | HTTP/SSE + stdio |
| **Authentication** | Basic | OAuth2 + JWT |
| **Scaling** | Single instance | Horizontal scaling |
| **Monitoring** | Manual setup | Built-in Prometheus/Grafana |
| **Security** | Basic SSL | Enterprise hardening |
| **Best For** | Development/Testing | Production |

---

## 🤝 Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Documentation**: [Complete documentation](docs/)
- **Security Issues**: [Security policy](SECURITY.md)
- **Community**: [Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Special Thanks**: [@marcolinux46](https://github.com/marcolinux46) for extensive testing and feedback
- **Wazuh Team**: For the excellent SIEM platform
- **Anthropic**: For the Claude AI models and MCP framework
- **Community**: All contributors and users providing feedback

---

## 📊 Project Status

- **Version**: v3.0.0 Docker (Production) / v2.0.0 Traditional (Stable)
- **Maintenance**: Active development and support
- **Security**: Regular security updates and patches
- **Compatibility**: Docker 20.10+ (v3) | Python 3.9+ (v2) | Wazuh 4.8+
- **Platforms**: Linux, macOS, Windows
- **License**: MIT License