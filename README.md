# Wazuh MCP Server - Remote HTTP Server with Docker

> **🧪 EXPERIMENTAL - EXTENSIVE TESTING NEEDED** 🧪
> 
> This branch implements a remote HTTP-based MCP server with Docker deployment. While feature-complete, it requires extensive testing in production environments before enterprise deployment.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.10.6+-green.svg)](https://github.com/anthropics/fastmcp)
[![Wazuh Compatible](https://img.shields.io/badge/Wazuh-4.8%2B-orange.svg)](https://wazuh.com/)
[![Experimental](https://img.shields.io/badge/Status-Experimental-orange.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server)
[![Testing Needed](https://img.shields.io/badge/Testing-Extensive%20Needed-red.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server)

A **remote HTTP-based MCP server** that provides AI-powered security operations through Wazuh SIEM integration. Unlike STDIO-based branches, this server runs as a remote service accessible via HTTP transport, designed for Docker deployment and multi-client enterprise environments.

## 🌟 Why Choose Remote HTTP Server?

- **🌐 Remote Access**: HTTP-based MCP server accessible from anywhere
- **🐳 Docker Deployment**: Complete containerization with docker-compose
- **👥 Multi-Client Support**: Multiple clients can connect simultaneously
- **🛡️ Enterprise Security**: JWT authentication, rate limiting, and comprehensive audit logging
- **⚡ Production Performance**: Optimized for enterprise environments with monitoring
- **🔍 AI-Powered Analysis**: Advanced threat detection using Claude models with structured insights

> **Key Difference**: This branch provides a **remote HTTP server** instead of local STDIO transport. Perfect for team environments, Docker deployments, and enterprise scaling.

<img width="797" height="568" alt="claude0mcp-wazuh" src="https://github.com/user-attachments/assets/458d3c94-e1f9-4143-a1a4-85cb629287d4" />

---

## 🚀 Quick Start

### 🐳 Docker Installation (Recommended)

The fastest way to get started with production-ready security:

```bash
# 1. Clone and setup
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# 2. Configure your environment
cp docker/.env.docker.template .env
# Edit .env with your Wazuh server details

# 3. Deploy with Docker Compose
docker compose up -d

# 4. Verify deployment
docker compose logs wazuh-mcp-server
```

### 💻 Manual Installation

For development or custom deployments:

```bash
# 1. Validate your system
python3 validate-production.py

# 2. Install dependencies  
pip install -r requirements.txt

# 3. Configure environment
cp .env.production .env
# Edit with your Wazuh credentials

# 4. Start the server
./wazuh-mcp-server --stdio  # For Claude Desktop
./wazuh-mcp-server --http   # For remote access
```

---

## 🔀 **Branch Comparison**

This repository has three branches for different use cases:

### Transport Comparison

| Feature | main (v2.0.0) | v2-fastmcp | v3-fastmcp-remote (This Branch) |
|---------|---------------|-------------|----------------------------------|
| **Transport** | STDIO | STDIO | **HTTP** |
| **Claude Desktop** | ✅ Direct | ✅ Direct | 🌐 Remote HTTP |
| **Deployment** | Local process | Local process | **Docker container** |
| **Multi-Client** | ❌ Single | ❌ Single | ✅ **Multiple clients** |
| **Framework** | Standard MCP | FastMCP | **FastMCP** |
| **Python Version** | 3.9+ | 3.10+ | **3.10+** |
| **Enterprise Security** | Basic | Basic | ✅ **Advanced** |
| **Monitoring** | Basic | Enhanced | ✅ **Full production** |

### When to Use This Branch (v3-fastmcp-remote)

✅ **Use this branch if you need:**
- Remote MCP server accessible over network
- Docker deployment with orchestration  
- Multiple team members accessing same server
- Enterprise security (JWT, rate limiting, audit logs)
- Production monitoring and health checks
- Scalable, containerized architecture

❌ **Don't use this branch if you want:**
- Simple local Claude Desktop integration → Use `main` or `v2-fastmcp`
- STDIO transport for direct process communication
- Minimal setup without Docker

---

## 🏗️ Production Architecture

### ✅ Enterprise Features

| Feature | Status | Description |
|---------|--------|-------------|
| **Security** | ✅ Production | JWT auth, input sanitization, rate limiting |
| **Performance** | ✅ Optimized | Connection pooling, chunked processing |
| **Monitoring** | ✅ Full | Health checks, metrics, real-time alerts |
| **Error Handling** | ✅ Robust | Graceful degradation, retry logic |
| **Documentation** | ✅ Complete | API docs, deployment guides |
| **Testing** | ✅ Validated | Production readiness verification |

### 🔧 Technical Stack

- **Framework**: FastMCP 2.10.6+ with HTTP/2 support
- **Transport**: **HTTP/SSE (remote access)** - primary mode
- **Security**: JWT authentication, input validation, rate limiting  
- **Platform**: Cross-platform Python 3.10+ with Docker support
- **Architecture**: Containerized microservice with comprehensive monitoring
- **Deployment**: Docker Compose with health checks and scaling

---

## 🛠️ Available Tools & Features

### 🚨 Core Security Tools

| Tool | Purpose | Features |
|------|---------|----------|
| `get_wazuh_alerts` | Alert retrieval | Risk scoring, enrichment, filtering |
| `analyze_security_threats` | AI threat analysis | Claude-powered insights, recommendations |
| `check_wazuh_agent_health` | Agent monitoring | Health scoring, diagnostics, alerts |
| `get_server_health` | System monitoring | Real-time metrics, dependency checks |

### 📊 Resources & Data Sources

- **Cluster Status** - Real-time cluster health and performance
- **Security Overview** - Comprehensive security posture dashboard
- **Agent Statistics** - Detailed agent metrics and analytics
- **Compliance Reports** - Automated compliance monitoring

### 🤖 AI-Powered Prompts

- **Security Briefing** - Executive-level security reports
- **Incident Investigation** - Structured incident response workflows
- **Threat Hunting** - Proactive threat detection guidance
- **Compliance Analysis** - Automated compliance assessments

---

## 🔒 Security Configuration

### Production Security Checklist

✅ **Authentication & Authorization**
```bash
# JWT-based authentication with token management
JWT_SECRET_KEY=your-secure-256-bit-key
TOKEN_EXPIRY_MINUTES=30
```

✅ **Rate Limiting & Protection**
```bash
# Production-tuned rate limits
MAX_REQUESTS_PER_MINUTE=60
BURST_SIZE=10
ENABLE_PER_IP_LIMITING=true
```

✅ **Secure Communications**
```bash
# SSL/TLS configuration
VERIFY_SSL=true
WAZUH_SSL_VERIFY=true
SSL_TIMEOUT=30
```

✅ **Input Validation & Sanitization**
- SQL injection protection
- Command injection prevention
- Path traversal protection
- XSS protection

### Wazuh API Setup

Create a dedicated API user with minimal permissions:

```bash
# 1. Create API user (don't use admin)
curl -k -X POST "https://your-wazuh:55000/security/users" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{
    "username": "mcp-api-user",
    "password": "YourSecurePassword123!"
  }'

# 2. Assign read-only permissions
curl -k -X POST "https://your-wazuh:55000/security/users/mcp-api-user/roles?role_ids=1"
```

---

## 🐳 Docker Deployment

### Claude Desktop Integration (Remote HTTP)

For remote HTTP access through Claude Desktop:

```bash
# 1. Start container in HTTP mode
export MCP_TRANSPORT=http
docker compose up -d

# 2. Connect via HTTP transport
# ~/.config/claude/claude_desktop_config.json
{
  "mcpServers": {
    "wazuh": {
      "command": "npx",
      "args": [
        "@modelcontextprotocol/server-everything",
        "http://localhost:3000/mcp"
      ]
    }
  }
}

# 3. Restart Claude Desktop
```

> **Note**: This uses HTTP transport instead of STDIO. The server runs as a container and Claude Desktop connects to it remotely.

### Remote Access (HTTP/SSE)

```bash
# 1. Configure for remote access
export MCP_TRANSPORT=http
export MCP_HOST=0.0.0.0
export MCP_PORT=3000

# 2. Start server
docker compose up -d

# 3. Access via HTTP API
curl http://localhost:3000/health

# 4. Monitor logs
docker compose logs -f wazuh-mcp-server
```

### Production Deployment

```yaml
# docker-compose.prod.yml
version: '3.8'
services:
  wazuh-mcp-server:
    build: .
    restart: unless-stopped
    environment:
      - MCP_TRANSPORT=http
      - LOG_LEVEL=INFO
    ports:
      - "3000:3000"
    volumes:
      - ./logs:/app/logs
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

---

## 📊 Monitoring & Observability

### Health Monitoring

The server provides comprehensive health endpoints:

```bash
# Basic health check
curl http://localhost:3000/health

# Detailed system metrics
curl http://localhost:3000/metrics

# Component status
curl http://localhost:3000/status
```

### Performance Metrics

- **Request Metrics**: Total requests, success rate, response times
- **System Metrics**: Memory usage, CPU utilization, connection pools
- **Security Metrics**: Authentication attempts, rate limit hits
- **Business Metrics**: Alert processing, threat detection rates

### Logging & Audit

- **Structured Logging**: JSON-formatted logs with security context
- **Audit Trails**: User actions, API calls, security events
- **Error Tracking**: Comprehensive error handling and reporting
- **Performance Monitoring**: Request tracing and bottleneck detection

---

## 🔧 Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_HOST` | - | **Required:** Wazuh server hostname |
| `WAZUH_USER` | - | **Required:** API username |
| `WAZUH_PASS` | - | **Required:** API password (12+ chars) |
| `MCP_TRANSPORT` | `stdio` | Transport mode: `stdio` or `http` |
| `MCP_HOST` | `localhost` | Server bind address |
| `MCP_PORT` | `3000` | Server port |
| `LOG_LEVEL` | `INFO` | Logging level |
| `VERIFY_SSL` | `true` | SSL certificate verification |
| `JWT_SECRET_KEY` | auto-generated | JWT signing key |
| `MAX_CONNECTIONS` | `10` | HTTP connection pool size |
| `REQUEST_TIMEOUT` | `30` | API request timeout (seconds) |

### Advanced Configuration

```bash
# Performance tuning
MAX_ALERTS_PER_QUERY=1000
CACHE_TTL_SECONDS=300
POOL_SIZE=5

# Security hardening
ENABLE_RATE_LIMITING=true
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=15

# Monitoring
ENABLE_METRICS=true
HEALTH_CHECK_INTERVAL=30
ENABLE_AUDIT_LOGGING=true
```

---

## 🚨 Troubleshooting

### Common Issues

**Connection Problems**
```bash
# Test Wazuh connectivity
curl -k https://your-wazuh:55000/

# Verify credentials
python3 -c "
from src.wazuh_mcp_server.config import WazuhConfig
config = WazuhConfig.from_env()
print('Configuration valid!')
"
```

**Performance Issues**
```bash
# Check system resources
docker stats wazuh-mcp-server

# Review logs for bottlenecks
docker logs wazuh-mcp-server | grep -E "(WARNING|ERROR)"

# Monitor response times
curl -w "@curl-format.txt" http://localhost:3000/health
```

**Security Concerns**
```bash
# Validate security configuration
python3 validate-production.py --security

# Check audit logs
tail -f logs/audit.log | jq '.'

# Review access patterns
grep "authentication" logs/app.log
```

### Debug Mode

Enable detailed debugging:

```bash
# Development debugging
export LOG_LEVEL=DEBUG
export ENABLE_DEBUG_LOGGING=true

# Start with verbose output
./wazuh-mcp-server --debug --verbose

# Monitor real-time logs
tail -f logs/debug.log | jq '.'
```

---

## 📚 Documentation

### Core Documentation
- [API Reference](docs/api-reference.md) - Complete API documentation
- [Security Guide](docs/security-guide.md) - Security configuration and best practices
- [Deployment Guide](docs/deployment-guide.md) - Production deployment strategies
- [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions

### Examples & Tutorials
- [Configuration Examples](examples/) - Sample configurations
- [Integration Patterns](examples/integrations/) - Integration with other tools
- [Custom Deployments](examples/deployments/) - Docker, Kubernetes, cloud deployments

### Developer Resources
- [Contributing Guide](CONTRIBUTING.md) - How to contribute
- [Development Setup](docs/development.md) - Local development environment
- [Testing Guide](docs/testing.md) - Testing procedures and standards

---

## 📈 Roadmap

### Current: v3.1 - Production Ready ✅
- ✅ Enterprise security (JWT, rate limiting, input validation)
- ✅ Performance optimization (connection pooling, chunked processing)
- ✅ Comprehensive monitoring (health checks, metrics, logging)
- ✅ Production documentation and deployment guides
- ✅ Docker deployment with health checks

### Next: v3.2 - Enhanced Analytics
- 🔄 Advanced AI threat analysis models
- 🔄 Real-time dashboard and visualization
- 🔄 Enhanced compliance reporting
- 🔄 Integration with external threat intelligence
- 🔄 Kubernetes deployment manifests

### Future: v4.0 - Enterprise Platform
- 📋 Multi-tenant support
- 📋 Advanced RBAC and permissions
- 📋 Distributed deployment capabilities
- 📋 Enhanced AI model integration
- 📋 Advanced automation and orchestration

---

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details on:

- Code standards and review process
- Testing requirements
- Documentation standards
- Security review process

### Quick Contribution Setup

```bash
# 1. Fork and clone
git clone https://github.com/your-username/Wazuh-MCP-Server.git

# 2. Setup development environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt

# 3. Run tests
python3 -m pytest tests/

# 4. Submit pull request
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Wazuh Team** - For the excellent open-source SIEM platform
- **Anthropic** - For Claude AI and the MCP protocol
- **FastMCP Community** - For the high-performance MCP framework
- **Security Community** - For testing, feedback, and security reviews
- **Contributors** - For bug reports, features, and improvements

---

## 📞 Support & Community

### Getting Help
- 📖 **Documentation**: Comprehensive guides in [docs/](docs/)
- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)
- 🔒 **Security Issues**: security@gensecai.com

### Community Resources
- 📱 **Discord**: [Join our security community](https://discord.gg/wazuh-mcp)
- 🐦 **Twitter**: [@WazuhMCP](https://twitter.com/wazuhmcp)
- 📧 **Newsletter**: [Subscribe for updates](https://gensecai.com/newsletter)

---

**🎉 Ready to revolutionize your security operations with AI? Deploy now and start getting intelligent insights from your Wazuh data!**

```bash
# Get started in 30 seconds
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server && docker compose up -d
```