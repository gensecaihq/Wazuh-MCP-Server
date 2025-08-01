# Wazuh MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue.svg)](https://hub.docker.com/)
[![Python 3.13+](https://img.shields.io/badge/Python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![MCP Compliant](https://img.shields.io/badge/MCP-Compliant-green.svg)](https://modelcontextprotocol.io/)

A production-ready, MCP-compliant remote server that provides seamless integration between AI assistants and Wazuh SIEM platform through the Model Context Protocol (MCP) with Server-Sent Events (SSE) transport.

## 🌟 Features

### Core Capabilities
- **🔗 MCP-Compliant Remote Server**: Full compliance with MCP 2025-03-26 specification
- **⚡ SSE Transport**: Real-time streaming with Server-Sent Events
- **🛡️ Production Security**: Rate limiting, input validation, CORS protection
- **📊 Comprehensive Monitoring**: Prometheus metrics, health checks, logging
- **🐳 Docker Native**: Multi-platform container support (AMD64/ARM64)
- **🔄 High Availability**: Circuit breakers, retry logic, graceful shutdown

### Wazuh Integration
- **🔍 Advanced Security Monitoring**: Real-time alert analysis and threat detection
- **👥 Agent Management**: Comprehensive agent lifecycle and health monitoring
- **🚨 Incident Response**: Automated threat hunting and response capabilities
- **📈 Security Analytics**: Performance metrics and compliance reporting
- **🌐 Multi-Environment**: Support for cloud, on-premise, and hybrid deployments

### 29 Specialized Tools
Comprehensive toolkit for security operations including:

**Alert Management (4 tools)**
- **get_wazuh_alerts**: Retrieve security alerts with filtering
- **get_wazuh_alert_summary**: Alert summaries grouped by field
- **analyze_alert_patterns**: Pattern analysis and anomaly detection
- **search_security_events**: Advanced security event search

**Agent Management (6 tools)**
- **get_wazuh_agents**: Agent information and status
- **get_wazuh_running_agents**: Active agent monitoring
- **check_agent_health**: Agent health status checks
- **get_agent_processes**: Running process inventory
- **get_agent_ports**: Open port monitoring
- **get_agent_configuration**: Agent configuration details

**Vulnerability Management (3 tools)**
- **get_wazuh_vulnerabilities**: Vulnerability assessments
- **get_wazuh_critical_vulnerabilities**: Critical vulnerability focus
- **get_wazuh_vulnerability_summary**: Vulnerability statistics

**Security Analysis (6 tools)**
- **analyze_security_threat**: AI-powered threat analysis
- **check_ioc_reputation**: IoC reputation checking
- **perform_risk_assessment**: Comprehensive risk analysis
- **get_top_security_threats**: Top threat identification
- **generate_security_report**: Automated security reporting
- **run_compliance_check**: Framework compliance validation

**System Monitoring (10 tools)**
- **get_wazuh_statistics**: Comprehensive system metrics
- **get_wazuh_weekly_stats**: Weekly trend analysis
- **get_wazuh_cluster_health**: Cluster health monitoring
- **get_wazuh_cluster_nodes**: Node status and information
- **get_wazuh_rules_summary**: Rule effectiveness analysis
- **get_wazuh_remoted_stats**: Agent communication statistics
- **get_wazuh_log_collector_stats**: Log collection metrics
- **search_wazuh_manager_logs**: Manager log search
- **get_wazuh_manager_error_logs**: Error log analysis
- **validate_wazuh_connection**: Connection validation

## 🚀 Quick Start

### Prerequisites
- **Docker** 20.10+ with Compose v2.20+
- **Python** 3.13+ (for development)
- **Wazuh** 4.x deployment with API access

### 1. Clone Repository
```bash
git clone <your-repository-url>
cd Wazuh-MCP-Server
```

### 2. Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit configuration (required)
nano .env
```

**Essential Configuration:**
```env
# Wazuh Server Connection
WAZUH_HOST=https://your-wazuh-server.com
WAZUH_USER=your-api-user
WAZUH_PASS=your-api-password
WAZUH_PORT=55000

# Server Configuration
MCP_HOST=0.0.0.0
MCP_PORT=3000

# Authentication
AUTH_SECRET_KEY=your-secret-key-here
```

### 3. Deploy with Docker
```bash
# Production deployment
./deploy-production.sh

# Or manually
docker compose up -d --wait
```

### 4. Verify Deployment
```bash
# Check service status
docker compose ps

# Health check
curl http://localhost:3000/health

# View logs
docker compose logs -f wazuh-mcp-server
```

## 📋 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `WAZUH_HOST` | Wazuh server URL | - | ✅ |
| `WAZUH_USER` | API username | - | ✅ |
| `WAZUH_PASS` | API password | - | ✅ |
| `WAZUH_PORT` | API port | `55000` | ❌ |
| `MCP_HOST` | Server bind address | `127.0.0.1` | ❌ |
| `MCP_PORT` | Server port | `3000` | ❌ |
| `AUTH_SECRET_KEY` | JWT signing key | - | ✅ |
| `LOG_LEVEL` | Logging level | `INFO` | ❌ |
| `WAZUH_VERIFY_SSL` | SSL verification | `false` | ❌ |
| `ALLOWED_ORIGINS` | CORS origins | `https://claude.ai` | ❌ |

### Docker Compose Configuration

The `compose.yml` follows Docker Compose v2 latest naming convention and includes:
- **Multi-platform builds** (AMD64/ARM64)
- **Security hardening** (non-root user, read-only filesystem)
- **Resource limits** (CPU/Memory constraints)
- **Health checks** with automatic recovery
- **Structured logging** with rotation

## 🔧 Development

### Local Development Setup

**Option 1: Docker Development Environment**
```bash
# Run with development compose file
docker compose -f compose.dev.yml up -d --build

# View logs
docker compose -f compose.dev.yml logs -f
```

**Option 2: Native Python Development**
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run development server
python -m wazuh_mcp_server
```

### Project Structure
```
src/wazuh_mcp_server/
├── __main__.py              # Application entry point
├── server.py                # MCP-compliant FastAPI server
├── config.py                # Configuration management
├── auth.py                  # Authentication & authorization
├── security.py              # Security middleware & validation
├── monitoring.py            # Metrics & health checks
├── resilience.py            # Circuit breakers & retry logic
├── api/
│   └── wazuh_client.py      # Wazuh API client
└── tools/                   # MCP tools implementation
    └── core.py              # 3 essential security tools
```

### Building Custom Images
```bash
# Build for current platform
docker build -t wazuh-mcp-server:custom .

# Multi-platform build
docker buildx build --platform linux/amd64,linux/arm64 -t wazuh-mcp-server:multi .
```

## 🛡️ Security

### Production Security Features
- **🔐 Authentication**: JWT-based API key authentication
- **🚫 Rate Limiting**: Per-client request throttling
- **🛡️ Input Validation**: SQL injection and XSS protection  
- **🌐 CORS Protection**: Configurable origin restrictions
- **🔒 TLS Support**: HTTPS/WSS encryption ready
- **👤 Non-root Execution**: Container security hardening

### Security Best Practices
```bash
# Generate secure API key
openssl rand -hex 32

# Set restrictive file permissions
chmod 600 .env
chmod 700 deploy-production.sh

# Regular security updates
docker compose pull
docker compose up -d
```

## 📊 Monitoring & Operations  

### Health Monitoring
```bash
# Application health
curl http://localhost:3000/health

# Detailed metrics
curl http://localhost:3000/metrics

# Container health
docker inspect wazuh-mcp-server --format='{{.State.Health.Status}}'
```

### Log Management
```bash
# Follow live logs
docker compose logs -f --timestamps wazuh-mcp-server

# Export logs
docker compose logs --since=24h wazuh-mcp-server > server.log
```

### Performance Monitoring
- **Prometheus Metrics**: `/metrics` endpoint
- **Health Checks**: `/health` with detailed status
- **Request Tracing**: Structured JSON logging
- **Resource Usage**: Docker stats integration

## 🔧 Management Commands

### Docker Compose Operations
```bash
# Deploy/Update
./deploy-production.sh

# View status
docker compose ps --format table

# Scale service
docker compose up --scale wazuh-mcp-server=2 -d

# Stop services  
docker compose down --timeout 30

# Full cleanup
docker compose down --volumes --remove-orphans
```

### Maintenance
```bash
# Update images
docker compose pull && docker compose up -d

# Backup configuration
tar -czf backup-$(date +%Y%m%d).tar.gz .env compose.yml

# View resource usage
docker stats wazuh-mcp-server --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}"
```

## 🌐 API Reference

### MCP Protocol Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET/POST | MCP protocol endpoint (SSE/JSON-RPC) |
| `/health` | GET | Health check and status |
| `/metrics` | GET | Prometheus metrics |
| `/docs` | GET | OpenAPI documentation |

### Authentication
```bash
# Get access token
curl -X POST http://localhost:3000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "your-api-key"}'

# Use token in requests
curl -H "Authorization: Bearer <token>" http://localhost:3000/
```

## 🤝 Integration

### Claude Desktop Integration
Add to your Claude Desktop configuration:
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "npx",
      "args": [
        "@modelcontextprotocol/server-fetch",
        "http://localhost:3000"
      ],
      "env": {
        "MCP_API_KEY": "your-api-key"
      }
    }
  }
}
```

### Programmatic Access
```python
import httpx

async def query_wazuh_mcp():
    async with httpx.AsyncClient() as client:
        # Initialize MCP session
        response = await client.post(
            "http://localhost:3000/",
            headers={"Authorization": "Bearer <token>"},
            json={
                "jsonrpc": "2.0",
                "id": "1",
                "method": "tools/list"
            }
        )
        return response.json()
```

## 🚨 Troubleshooting

### Common Issues

**Connection Refused**
```bash
# Check service status
docker compose ps
docker compose logs wazuh-mcp-server

# Verify port availability
netstat -ln | grep 3000
```

**Authentication Errors** 
```bash
# Verify Wazuh credentials
curl -u "$WAZUH_USER:$WAZUH_PASS" "$WAZUH_HOST:$WAZUH_PORT/"

# Check API key configuration
grep API_KEY .env
```

**SSL/TLS Issues**
```bash
# Disable SSL verification for testing
echo "WAZUH_VERIFY_SSL=false" >> .env
docker compose up -d
```

### Support Resources
- **📖 Documentation**: [MCP Specification](https://modelcontextprotocol.io/)  
- **🐛 Issues**: Check your repository's issues section
- **💬 Discussions**: Repository discussions section

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **[Wazuh](https://wazuh.com/)** - Open source security platform
- **[Model Context Protocol](https://modelcontextprotocol.io/)** - AI assistant integration standard  
- **[FastAPI](https://fastapi.tiangolo.com/)** - Modern Python web framework
- **[Docker](https://www.docker.com/)** - Containerization platform

---

**Built for the security community with production-ready MCP compliance.**