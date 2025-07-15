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
- **Remote MCP**: Connect from anywhere with HTTP/SSE transport and OAuth2 authentication
- **Production Deployment**: Full Docker stack with monitoring, high availability, and security hardening

<img width="797" height="568" alt="claude0mcp-wazuh" src="https://github.com/user-attachments/assets/458d3c94-e1f9-4143-a1a4-85cb629287d4" />

## 🏷️ Version Information

### **Production Release: v3.0.0** (Current - July 15, 2025)
- **Status**: ✅ **Production Ready** - [GitHub Release](https://github.com/gensecaihq/Wazuh-MCP-Server/releases/tag/v3.0.0)
- **New Features**: Remote MCP server, OAuth2 authentication, Docker deployment, High Availability
- **Transport**: HTTP/SSE for remote access + stdio for local development
- **Best For**: Production environments requiring remote access and enterprise security
- **Tools**: 26 advanced security tools with comprehensive monitoring

### **Previous Stable: v2.0.0** 
- **Status**: ✅ **Stable** - [GitHub Release](https://github.com/gensecaihq/Wazuh-MCP-Server/releases/tag/v2.0.0)
- **Features**: 26 security tools with Phase 5 enhancement system
- **Transport**: stdio (local only)
- **Best For**: Local development and testing environments

### **Legacy: v1.0.0** 
- **Status**: ✅ **Legacy Support** - [GitHub Release](https://github.com/gensecaihq/Wazuh-MCP-Server/releases/tag/v1.0.0)
- **Features**: 14 core security tools
- **Best For**: Minimal installations and legacy systems

> **💡 Recommendation**: Use **v3.0.0** for all production deployments with remote access capabilities. Previous versions remain fully supported for backward compatibility.

## 🚀 Quick Start

Choose your deployment method based on your needs:

### 🐳 Option 1: Production Docker Deployment (Recommended)

**Complete production stack with monitoring, high availability, and security:**

```bash
# Clone the repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Create production environment
cp .env.example .env
# Edit .env with your Wazuh details and secure credentials

# Deploy production stack
docker compose -f docker-compose.ha.yml up -d

# Verify deployment
docker compose -f docker-compose.ha.yml ps
curl -f http://localhost:8443/health
```

**What you get:**
- 🔐 OAuth2 authentication with JWT tokens
- 🌐 Remote MCP access via HTTP/SSE
- 📊 Prometheus + Grafana monitoring
- 🔄 High availability with load balancing
- 🛡️ Security hardening and audit logging
- 📋 Automated backups and incident response

### 🔧 Option 2: Local Development Setup

**For development and testing:**

```bash
# Clone and install
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
python3 scripts/install.py

# Configure environment
cp .env.example .env
# Edit .env with your Wazuh details

# Run locally (stdio mode)
python3 -m wazuh_mcp_server.main --stdio
```

### 🌍 Option 3: Remote MCP Server

**For remote access without full production stack:**

```bash
# Install dependencies
pip install -r requirements.txt

# Set environment variables
export WAZUH_API_URL=https://your-wazuh-manager:55000
export WAZUH_API_USERNAME=your_username
export WAZUH_API_PASSWORD=your_password
export JWT_SECRET_KEY=$(openssl rand -base64 32)

# Start remote server
python3 -m wazuh_mcp_server.remote_server \
  --host 0.0.0.0 \
  --port 8443 \
  --transport sse
```

## 🔧 Configuration

### Environment Variables

Create `.env` file with your configuration:

```env
# Wazuh Configuration (Required)
WAZUH_HOST=your-wazuh-server.com
WAZUH_USER=your-username
WAZUH_PASS=your-password
WAZUH_PORT=55000
WAZUH_INDEXER_HOST=your-indexer.com
WAZUH_INDEXER_PORT=9200

# Server Configuration (v3.0.0 Remote MCP)
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8443
MCP_TRANSPORT=sse

# Authentication (Production)
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

### Claude Desktop Configuration

#### For Local Development (stdio)
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

#### For Remote Access (v3.0.0)
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

## 🎯 Features

### 🔍 Security Tools (26 Total)

#### Core Security Operations
- **get_alerts**: Retrieve and filter Wazuh alerts
- **analyze_threats**: AI-powered threat analysis
- **check_agent_health**: Monitor agent status
- **compliance_check**: Compliance assessments (PCI DSS, GDPR, HIPAA, etc.)
- **risk_assessment**: Comprehensive security risk analysis
- **vulnerability_prioritization**: Risk-based vulnerability management

#### Advanced Analytics
- **get_wazuh_alert_summary**: Statistical alert analysis
- **get_wazuh_weekly_stats**: Weekly security statistics
- **get_wazuh_vulnerability_summary**: Vulnerability insights
- **get_wazuh_critical_vulnerabilities**: Critical vulnerability tracking
- **get_wazuh_cluster_health**: Cluster monitoring
- **search_wazuh_manager_logs**: Log analysis

#### AI Enhancement Features
- **Security Incident Analysis**: Structured incident investigation
- **Threat Hunting**: Proactive threat detection strategies
- **Compliance Assessment**: Framework-specific compliance analysis
- **Forensic Analysis**: Digital forensics investigation
- **Security Reporting**: Executive and technical security reports

### 🔐 Enterprise Security (v3.0.0)

#### Authentication & Authorization
- **OAuth 2.0 Server**: Full authorization server with client management
- **JWT Token Management**: Secure token creation, validation, and revocation
- **Scope-based Access**: Granular permissions (`read:alerts`, `read:agents`, etc.)
- **Multi-client Support**: Support for multiple OAuth2 clients

#### Security Hardening
- **Rate Limiting**: Per-client rate limiting with abuse protection
- **SSL/TLS Support**: Full HTTPS with certificate management
- **Security Headers**: Comprehensive HTTP security headers
- **Audit Logging**: Complete security event logging

### 📊 Monitoring & Observability

#### Metrics Collection
- **Prometheus Integration**: Custom metrics and dashboards
- **Grafana Dashboards**: Pre-configured monitoring dashboards
- **Health Endpoints**: Comprehensive health checks
- **Performance Metrics**: Request rates, response times, error rates

#### Logging & Tracing
- **Structured Logging**: JSON logs with correlation IDs
- **Audit Trails**: Security event tracking
- **Distributed Tracing**: OpenTelemetry integration
- **Error Tracking**: Comprehensive error context

### 🏗️ Production Features

#### High Availability
- **Load Balancing**: HAProxy with health checks
- **Auto-Recovery**: Automatic failover and recovery
- **Scaling**: Horizontal scaling support
- **Backup Systems**: Automated backup and recovery

#### Deployment Options
- **Docker Compose**: Complete production stack
- **Kubernetes**: Production-ready manifests
- **Bare Metal**: Direct server deployment
- **Cloud Native**: AWS, Azure, GCP support

## 🔌 Integration Options

### Claude Desktop (Local)
- **Setup**: Add to `claude_desktop_config.json`
- **Transport**: stdio for local development
- **Best For**: Development and testing

### Claude Code (Remote)
- **Setup**: URL-based remote MCP connection
- **Transport**: HTTP/SSE with OAuth2
- **Best For**: Production remote access

### API Integration
- **REST API**: Standard HTTP endpoints
- **OpenAPI**: Interactive documentation at `/docs`
- **SDKs**: Python, JavaScript, Go clients available

## 📋 API Reference

### Health & Status
- `GET /health` - Health check endpoint
- `GET /info` - Server information
- `GET /metrics` - Prometheus metrics

### Authentication
- `GET /oauth/authorize` - OAuth2 authorization
- `POST /oauth/token` - Token exchange
- `POST /oauth/revoke` - Token revocation

### MCP Communication
- `GET /sse` - Server-Sent Events endpoint
- `POST /mcp/tools` - Execute MCP tools
- `GET /mcp/capabilities` - Server capabilities

## 🛠️ Development

### Local Development
```bash
# Setup development environment
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Start development server
python3 -m wazuh_mcp_server.main --stdio
```

### Code Quality
```bash
# Format code
black src/ tests/

# Lint code
ruff src/ tests/

# Type checking
mypy src/

# Security scanning
bandit -r src/
```

## 🧪 Testing

### Test Categories
- **Unit Tests**: Individual component testing
- **Integration Tests**: Component interaction testing
- **E2E Tests**: End-to-end workflow testing
- **Security Tests**: Authentication and authorization
- **Performance Tests**: Load and stress testing

### Run Tests
```bash
# All tests
pytest

# Specific categories
pytest tests/unit/
pytest tests/integration/
pytest tests/security/
pytest tests/performance/

# With coverage
pytest --cov=src --cov-report=html
```

## 📈 Performance

### Benchmarks (v3.0.0)
- **Startup Time**: < 5 seconds
- **Memory Usage**: < 512MB under normal load
- **Response Time**: < 200ms (p95)
- **Concurrent Connections**: 1000+ supported
- **Request Rate**: 10,000+ requests/minute

### Optimization Features
- **Connection Pooling**: Efficient HTTP connection reuse
- **Caching**: LRU cache with TTL (60-90% API call reduction)
- **Async I/O**: Non-blocking operations
- **Request Batching**: Bulk operations support

## 🔧 Troubleshooting

### Common Issues

#### Connection Issues
```bash
# Test your setup
python scripts/validate_setup.py

# Check Wazuh connectivity
curl -u username:password https://your-wazuh:55000/

# Check remote server health
curl -f http://localhost:8443/health
```

#### Authentication Issues
**Problem**: "Invalid credentials" error despite correct dashboard login

**Solution**: Wazuh Dashboard and API use separate authentication systems.

1. **Create API User**:
   - Login to Wazuh Dashboard
   - Go to **Security** → **Internal users**
   - Create a new user with `wazuh` backend role
   - Use these credentials in your `.env` file

2. **Test API Authentication**:
   ```bash
   curl -k -X POST "https://your-wazuh:55000/security/user/authenticate" \
     -H "Content-Type: application/json" \
     -d '{"username":"your-api-user","password":"your-api-password"}'
   ```

#### Docker Issues
```bash
# Check container status
docker-compose ps

# View logs
docker-compose logs -f wazuh-mcp-server

# Restart services
docker-compose restart

# Clean deployment
docker compose down -v
docker compose up -d
```

#### SSL Issues
**For production** (recommended):
```env
VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=true
```

**For development only**:
```env
VERIFY_SSL=false
WAZUH_ALLOW_SELF_SIGNED=true
```

### Platform-Specific Issues

#### macOS/Linux
- Use the wrapper script for optimal compatibility
- Ensure execute permissions: `chmod +x scripts/mcp_wrapper.sh`
- Check file system permissions for log directories

#### Windows
- Use direct Python execution
- Ensure Python is in PATH
- Install Visual Studio Build Tools if needed

## 📚 Documentation

### 📖 User Guides
- [Claude Desktop Setup Guide](docs/user-guides/claude-desktop-setup.md) - Complete setup instructions
- [Production Deployment Guide](docs/operations/PRODUCTION_DEPLOYMENT.md) - Production setup
- [Migration Guide](docs/MIGRATION_GUIDE.md) - Upgrade from previous versions

### 🔧 Technical Documentation
- [v3.0.0 README](docs/v3/README_v3.md) - Complete v3.0.0 documentation
- [API Documentation](docs/api/README.md) - RESTful API reference
- [Security Guide](docs/security/README.md) - Security configuration
- [Monitoring Guide](docs/monitoring/README.md) - Observability setup

### 🚀 Operations
- [High Availability Setup](docs/operations/HIGH_AVAILABILITY.md) - HA configuration
- [Backup & Recovery](docs/operations/BACKUP_RECOVERY.md) - Data protection
- [Incident Response](docs/operations/INCIDENT_RESPONSE.md) - Emergency procedures
- [Runbooks](docs/operations/RUNBOOKS.md) - Operational procedures

### 💻 Development
- [Contributing Guidelines](docs/development/CONTRIBUTING.md) - How to contribute
- [Architecture Overview](docs/development/ARCHITECTURE.md) - System design
- [Testing Guide](docs/development/TESTING.md) - Testing procedures

### 🛠️ Troubleshooting
- [Unix Troubleshooting](docs/troubleshooting/unix-troubleshooting.md) - macOS/Linux issues
- [Windows Troubleshooting](docs/troubleshooting/windows-troubleshooting.md) - Windows issues
- [Docker Troubleshooting](docs/troubleshooting/docker-troubleshooting.md) - Container issues

## 🔄 Migration & Compatibility

### From v2.0.0 to v3.0.0
- **Backward Compatibility**: All v2.0.0 tools continue to work unchanged
- **New Features**: Remote MCP, OAuth2, Docker deployment available
- **Configuration**: Existing `.env` files compatible with new options
- **Migration Script**: `./scripts/migrate_v2_to_v3.sh`

### From v1.0.0 to v3.0.0
- **Tool Compatibility**: All v1.0.0 tools supported
- **Configuration Updates**: Minor environment variable additions
- **Feature Enhancements**: All tools benefit from Phase 5 enhancements
- **Migration Guide**: See [MIGRATION_GUIDE.md](docs/MIGRATION_GUIDE.md)

## 🏆 What's New in v3.0.0

### 🚀 Remote MCP Server
- **HTTP/SSE Transport**: Production-grade remote access
- **OAuth2 Authentication**: Enterprise security with JWT tokens
- **RESTful API**: Standard HTTP endpoints for all operations
- **Claude Code Integration**: Native remote MCP support

### 🐳 Docker Production Stack
- **Multi-stage Build**: Optimized container with security hardening
- **High Availability**: Load balancing with auto-recovery
- **Monitoring Stack**: Prometheus + Grafana + AlertManager
- **Security Features**: Non-root user, read-only filesystem, audit logging

### 📊 Enterprise Features
- **Production Monitoring**: Comprehensive metrics and alerting
- **Audit Logging**: Complete security event tracking
- **Automated Backups**: Disaster recovery with S3 integration
- **Incident Response**: Automated incident handling procedures

## 🤝 Support

- **GitHub Issues**: [Report bugs and request features](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Documentation**: [Complete documentation](docs/)
- **Security Issues**: [Security policy](SECURITY.md)
- **Community**: [Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Special Thanks**: [@marcolinux46](https://github.com/marcolinux46) for extensive testing and feedback
- **Wazuh Team**: For the excellent SIEM platform
- **Anthropic**: For the Claude AI models and MCP framework
- **Community**: All contributors and users providing feedback

## 📊 Project Status

- **Version**: v3.0.0 (Production Ready)
- **Maintenance**: Active development and support
- **Security**: Regular security updates and patches
- **Compatibility**: Python 3.9+ | Wazuh 4.8+ | Docker 20.10+
- **Platforms**: Linux, macOS, Windows
- **License**: MIT License