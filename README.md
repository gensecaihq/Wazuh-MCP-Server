# Wazuh MCP Remote Server v4.0.1


[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Supported-blue.svg)](https://hub.docker.com/)
[![Python 3.13+](https://img.shields.io/badge/Python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![MCP Compliant](https://img.shields.io/badge/MCP-2025--06--18-green.svg)](https://modelcontextprotocol.io/)
[![Streamable HTTP](https://img.shields.io/badge/Streamable%20HTTP-Enabled-blue.svg)](#)
[![Legacy SSE](https://img.shields.io/badge/Legacy%20SSE-Supported-orange.svg)](#)
[![OAuth 2.0](https://img.shields.io/badge/OAuth%202.0-DCR-green.svg)](#)
[![Bearer Auth](https://img.shields.io/badge/Bearer-Authentication-red.svg)](#)

A **production-ready, enterprise-grade** MCP-compliant remote server that provides seamless integration with Wazuh SIEM platform using the latest **Streamable HTTP transport** (MCP 2025-06-18).

> **Latest Standard**: Streamable HTTP transport with `/mcp` endpoint (2025-06-18)
>
> **Backwards Compatible**: Legacy `/sse` endpoint maintained
>
> **Compliance**: ✅ 100% compliant with MCP 2025-06-18 specification

## 🌟 Features

### Core Capabilities
- **🔗 MCP-Compliant Remote Server**: Full compliance with MCP 2025-06-18 specification
- **⚡ Streamable HTTP Transport**: Modern `/mcp` endpoint with dynamic SSE upgrade
- **🔄 Backwards Compatible**: Legacy `/sse` endpoint for older clients
- **📡 Protocol Versioning**: Supports 2025-06-18, 2025-03-26, and 2024-11-05
- **🔐 Bearer Token Authentication**: JWT-based authentication for secure remote access
- **🛡️ Production Security**: Rate limiting, input validation, CORS protection, origin validation
- **📊 Comprehensive Monitoring**: Prometheus metrics, health checks, structured logging
- **🐳 100% Containerized**: Everything in Docker - OS-agnostic deployment (Windows/macOS/Linux)
- **🌍 Zero Host Dependencies**: No Python, tools, or libraries needed on host system
- **🔄 High Availability**: Integrated circuit breakers, exponential backoff retry logic, graceful shutdown with connection draining
- **☁️ Serverless Ready**: Pluggable session storage (Redis or in-memory), stateless operations, horizontal scaling support

### 🏅 MCP 2025-06-18 Specification Compliance

This implementation **100% complies** with the latest MCP specification:

| Standard | Status | Implementation |
|----------|--------|----------------|
| **🔗 Streamable HTTP** | ✅ COMPLIANT | `/mcp` endpoint with POST/GET/DELETE support |
| **📡 Protocol Versioning** | ✅ COMPLIANT | MCP-Protocol-Version header validation |
| **⚡ Dynamic Streaming** | ✅ COMPLIANT | JSON or SSE based on Accept header |
| **🔐 Authentication** | ✅ COMPLIANT | Bearer token (JWT) authentication |
| **🛡️ Security** | ✅ COMPLIANT | HTTPS, origin validation, rate limiting |
| **🔄 Legacy Support** | ✅ COMPLIANT | Legacy `/sse` endpoint maintained |
| **📋 Session Management** | ✅ COMPLIANT | Full session lifecycle with DELETE support |

**Perfect Score: 33/33 Requirements Met** ⭐

📋 **[View Full Compliance Verification →](MCP_COMPLIANCE_VERIFICATION.md)**

**References:**
- [MCP Specification 2025-06-18](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports)
- [Streamable HTTP Transport Guide](https://blog.fka.dev/blog/2025-06-06-why-mcp-deprecated-sse-and-go-with-streamable-http/)
- [MCP Server Development](https://modelcontextprotocol.io/docs/develop/build-server)

### Wazuh Integration

**Supported Wazuh Versions**: 4.8.0 - 4.14.1 ✅

- **🔍 Advanced Security Monitoring**: Real-time alert analysis and threat detection
- **👥 Agent Management**: Comprehensive agent lifecycle and health monitoring
- **🚨 Incident Response**: Automated threat hunting and response capabilities
- **📈 Security Analytics**: Performance metrics and compliance reporting
- **🌐 Multi-Environment**: Support for cloud, on-premise, and hybrid deployments
- **🆕 Latest Features**: Full support for Wazuh 4.14.1 enhancements including improved vulnerability scanning and AWS integrations

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
- **Python** 3.9+ (optional, for OS-agnostic deployment script)
- **Wazuh** 4.8.0 - 4.14.1 deployment with API access

> **OS-Agnostic Deployment**: Everything runs in Docker containers. Works on Windows, macOS, and Linux identically.

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
# Windows: notepad .env
# macOS/Linux: nano .env
```

**Essential Configuration:**
```env
# Wazuh Server Connection
WAZUH_HOST=https://your-wazuh-server.com
WAZUH_USER=your-api-user
WAZUH_PASS=your-api-password
WAZUH_PORT=55000

# MCP Remote Server Configuration
MCP_HOST=0.0.0.0
MCP_PORT=3000

# Authentication (JWT Secret Key)
AUTH_SECRET_KEY=your-secret-key-here

# CORS for Claude Desktop
ALLOWED_ORIGINS=https://claude.ai,https://*.anthropic.com
```

### 3. Deploy with Docker (OS-Agnostic)

**Option 1: Python Deployment Script (Recommended - Works on all platforms)**
```bash
# Windows
python deploy.py

# macOS/Linux
python3 deploy.py
```

**Option 2: Platform-Specific Scripts**
```bash
# Linux/macOS
./deploy-production.sh

# Windows (PowerShell/CMD)
deploy.bat

# Or use Docker Compose directly (all platforms)
docker compose up -d --wait
```

### 4. Get Authentication Token
```bash
# Server will generate an API key on startup (check logs)
docker compose logs wazuh-mcp-remote-server | grep "API key"

# Exchange API key for JWT token
curl -X POST http://localhost:3000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "wazuh_your-generated-api-key"}'
```

### 5. Verify MCP Endpoint
```bash
# Test the official /sse endpoint
curl -H "Authorization: Bearer your-jwt-token" \
     -H "Origin: http://localhost" \
     -H "Accept: text/event-stream" \
     http://localhost:3000/sse

# Check service status
docker compose ps

# Health check
curl http://localhost:3000/health
```

## 📋 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `WAZUH_HOST` | Wazuh server URL | - | ✅ |
| `WAZUH_USER` | API username | - | ✅ |
| `WAZUH_PASS` | API password | - | ✅ |
| `WAZUH_PORT` | API port | `55000` | ❌ |
| `MCP_HOST` | Server bind address | `0.0.0.0` | ❌ |
| `MCP_PORT` | Server port | `3000` | ❌ |
| `AUTH_MODE` | Authentication mode: `oauth`, `bearer`, `none` | `bearer` | ❌ |
| `AUTH_SECRET_KEY` | JWT signing key | auto-generated | ❌ |
| `OAUTH_ENABLE_DCR` | Enable OAuth Dynamic Client Registration | `true` | ❌ |
| `LOG_LEVEL` | Logging level | `INFO` | ❌ |
| `WAZUH_VERIFY_SSL` | SSL verification | `false` | ❌ |
| `ALLOWED_ORIGINS` | CORS origins | `https://claude.ai` | ❌ |
| `REDIS_URL` | Redis URL for serverless sessions | - | ❌ |
| `SESSION_TTL_SECONDS` | Session TTL (Redis only) | `1800` | ❌ |

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

## 🚀 Advanced Features

### High Availability (HA)

The server includes production-grade HA features for maximum reliability:

**Circuit Breakers**
- Automatically opens after 5 consecutive failures
- Prevents cascading failures to Wazuh API
- Recovers automatically after 60 seconds
- Falls back gracefully during outages

**Retry Logic**
- Exponential backoff with jitter
- 3 retry attempts with 1-10 second delays
- Applies to all Wazuh API calls
- Handles transient network failures

**Graceful Shutdown**
- Waits for active connections to complete (max 30s)
- Runs cleanup tasks before termination
- Prevents data loss during restarts
- Integrates with Docker health checks

**Implementation:**
```python
# Automatically applied to all Wazuh API calls
# No configuration required - works out of the box
```

### Serverless Ready

Enable horizontally scalable, serverless deployments with external session storage:

**Default Mode: In-Memory Sessions**
```bash
# Single-instance deployments (default)
# No configuration needed
docker compose up -d
```
- ✅ Zero configuration
- ✅ Works immediately
- ❌ Sessions lost on restart
- ❌ Cannot scale horizontally

**Serverless Mode: Redis Sessions**
```bash
# Multi-instance/serverless deployments
# Configure Redis in .env file
REDIS_URL=redis://redis:6379/0
SESSION_TTL_SECONDS=1800  # 30 minutes

# Deploy with Redis
docker compose -f compose.yml -f compose.redis.yml up -d
```
- ✅ Sessions persist across restarts
- ✅ Horizontal scaling support
- ✅ Serverless compatible (AWS Lambda, Cloud Run)
- ✅ Automatic session expiration

**Redis Setup (Optional):**
```yaml
# compose.redis.yml
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s

volumes:
  redis-data:
```

**Verification:**
```bash
# Check session storage mode
curl http://localhost:3000/health | jq '.session_storage'

# Output:
# {
#   "type": "InMemorySessionStore"  # or "RedisSessionStore"
#   "sessions_count": 5
# }
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
| `/mcp` | GET/POST | **Recommended MCP endpoint** (Streamable HTTP - 2025-06-18) |
| `/sse` | GET | Legacy SSE endpoint (backward compatibility) |
| `/` | POST | JSON-RPC 2.0 endpoint (alternative API access) |
| `/health` | GET | Health check and status |
| `/metrics` | GET | Prometheus metrics |
| `/docs` | GET | OpenAPI documentation |

### Authentication Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/token` | POST | Exchange API key for JWT token (bearer mode) |
| `/.well-known/oauth-authorization-server` | GET | OAuth 2.0 discovery (oauth mode) |
| `/oauth/authorize` | GET | OAuth authorization endpoint |
| `/oauth/token` | POST | OAuth token exchange |
| `/oauth/register` | POST | Dynamic Client Registration (DCR) |

> **Claude Desktop**: Use `/mcp` endpoint with OAuth mode for best experience

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

## 🤖 Claude Desktop Integration

> **Important:** Claude Desktop supports remote MCP servers through the **Connectors UI**, not via the `claude_desktop_config.json` file. The JSON config file only supports local stdio-based MCP servers.

### Prerequisites

- **Claude Pro, Max, Team, or Enterprise plan** (required for custom connectors)
- Your Wazuh MCP Server deployed and accessible via **HTTPS**
- Custom Connectors feature is currently in **beta**

### Step 1: Deploy Your Server

Ensure your Wazuh MCP Server is running and publicly accessible:

```bash
# Deploy the server
docker compose up -d

# Verify it's running (must be HTTPS in production)
curl https://your-server-domain.com/health
```

### Step 2: Add Custom Connector in Claude Desktop

1. Open **Claude Desktop**
2. Go to **Settings** → **Connectors**
3. Click **"Add custom connector"**
4. Enter your MCP server URL:
   - **Recommended (Streamable HTTP):** `https://your-server-domain.com/mcp`
   - **Legacy (SSE):** `https://your-server-domain.com/sse`
5. In **Advanced settings**, add your Bearer token for authentication
6. Click **Connect**

### Step 3: Enable Tools in Chat

1. In your chat interface, click the **"Search and tools"** button
2. Find your Wazuh connector in the list
3. Click **"Connect"** to authenticate (if required)
4. Enable/disable specific tools as needed

### Authentication Modes

The server supports three authentication modes configured via `AUTH_MODE` environment variable:

| Mode | `AUTH_MODE` | Use Case | Claude Desktop Support |
|------|-------------|----------|----------------------|
| **OAuth** | `oauth` | Production with Claude Desktop | ✅ Native (recommended) |
| **Bearer Token** | `bearer` | API/Programmatic access | ✅ Via Advanced settings |
| **Authless** | `none` | Development/Testing | ✅ Direct connect |

---

#### Option A: OAuth (Recommended for Claude Desktop)

OAuth with Dynamic Client Registration (DCR) provides the best Claude Desktop experience.

```bash
# Set environment variable
AUTH_MODE=oauth docker compose up -d
```

**How it works:**
1. Claude Desktop discovers OAuth endpoints via `/.well-known/oauth-authorization-server`
2. Automatically registers as a client (DCR)
3. Handles authorization flow seamlessly

**OAuth Endpoints:**
- Discovery: `/.well-known/oauth-authorization-server`
- Authorization: `/oauth/authorize`
- Token: `/oauth/token`
- Registration: `/oauth/register` (DCR)

---

#### Option B: Bearer Token (Programmatic Access)

For API access or when OAuth is not available:

```bash
# Default mode
AUTH_MODE=bearer docker compose up -d
```

**Step 1: Get API Key**
```bash
docker compose logs wazuh-mcp-remote-server | grep "API key"
```

**Step 2: Exchange for JWT Token**
```bash
curl -X POST https://your-server-domain.com/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "wazuh_your-generated-api-key"}'
```

**Step 3: Use Bearer Token**
Add the token in Claude Desktop's Advanced settings or API requests.

---

#### Option C: Authless (Development Only)

For local development and testing only. **Not recommended for production.**

```bash
AUTH_MODE=none docker compose up -d
```

No authentication required - clients connect directly.

---

### Supported Features

| Feature | Status |
|---------|--------|
| Tools | ✅ Supported |
| Prompts | ✅ Supported |
| Resources | ✅ Supported |
| Text/Image Results | ✅ Supported |
| Resource Subscriptions | ❌ Not yet supported |
| Sampling | ❌ Not yet supported |

### ⚠️ Common Mistake: Using JSON Config for Remote Servers

**❌ This will NOT work** — the JSON config is for local stdio servers only:
```json
{
  "mcpServers": {
    "wazuh-security": {
      "url": "https://your-server.com/mcp",
      "headers": { "Authorization": "Bearer ..." }
    }
  }
}
```

This produces the error:
```
Could not load app settings
"path": ["mcpServers", "wazuh-security", "command"]
"message": "Required"
```

**✅ Correct approach:** Use **Settings → Connectors** UI as described above.

> **Requirements Checklist:**
> - ✅ Claude Pro, Max, Team, or Enterprise plan
> - ✅ Use **Connectors UI** (Settings → Connectors), NOT `claude_desktop_config.json`
> - ✅ Server must be accessible via **HTTPS** (production)
> - ✅ Use `/mcp` endpoint (Streamable HTTP) or `/sse` endpoint (legacy)
> - ✅ Authentication: OAuth (recommended), Bearer token, or Authless (dev only)

### Programmatic Access

**Using the official /sse endpoint:**
```python
import httpx
import asyncio

async def connect_to_mcp_sse():
    """Connect to MCP server using SSE endpoint."""
    async with httpx.AsyncClient() as client:
        # Get authentication token first
        auth_response = await client.post(
            "http://localhost:3000/auth/token",
            json={"api_key": "your-api-key"}
        )
        token = auth_response.json()["access_token"]
        
        # Connect to SSE endpoint
        async with client.stream(
            "GET",
            "http://localhost:3000/sse",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "text/event-stream",
                "Origin": "http://localhost"
            }
        ) as response:
            async for chunk in response.aiter_text():
                print(f"Received: {chunk}")

# Run the SSE client
asyncio.run(connect_to_mcp_sse())
```

**Using JSON-RPC endpoint (alternative):**
```python
import httpx

async def query_wazuh_mcp():
    async with httpx.AsyncClient() as client:
        # Get authentication token
        auth_response = await client.post(
            "http://localhost:3000/auth/token",
            json={"api_key": "your-api-key"}
        )
        token = auth_response.json()["access_token"]
        
        # Make JSON-RPC request
        response = await client.post(
            "http://localhost:3000/",
            headers={
                "Authorization": f"Bearer {token}",
                "Origin": "http://localhost"
            },
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

**MCP `/sse` Endpoint Issues**
```bash
# Test SSE endpoint authentication
curl -I http://localhost:3000/sse
# Expected: 401 Unauthorized (good - auth required)

# Test with valid token
curl -H "Authorization: Bearer your-jwt-token" \
     -H "Origin: http://localhost" \
     -H "Accept: text/event-stream" \
     http://localhost:3000/sse
# Expected: 200 OK with SSE stream

# Get new authentication token
curl -X POST http://localhost:3000/auth/token \
     -H "Content-Type: application/json" \
     -d '{"api_key": "your-api-key"}'
```

**Claude Desktop Connection Issues**
```bash
# Verify Claude Desktop can reach the server
curl http://localhost:3000/health
# Expected: {"status": "healthy"}

# Check CORS configuration
grep ALLOWED_ORIGINS .env
# Should include: https://claude.ai,https://*.anthropic.com
```

**Connection Refused**
```bash
# Check service status
docker compose ps
docker compose logs wazuh-mcp-remote-server

# Verify port availability
netstat -ln | grep 3000
```

**Authentication Errors** 
```bash
# Verify Wazuh credentials
curl -u "$WAZUH_USER:$WAZUH_PASS" "$WAZUH_HOST:$WAZUH_PORT/"

# Check API key in server logs
docker compose logs wazuh-mcp-remote-server | grep "API key"
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

---

## 🤝 Contributors Wanted

### 🧪 Help Us Test & Improve

We're looking for **hands-on testers** to deploy this MCP server in real-world environments and provide feedback!

**What We Need:**
- Deploy the server step-by-step following the documentation
- Test with actual Wazuh installations (v4.8.0 - v4.14.1)
- Try different deployment scenarios:
  - Single-instance (in-memory sessions)
  - Multi-instance with Redis (serverless mode)
  - Various OS platforms (Linux/macOS/Windows)
  - Different Wazuh configurations

**How to Contribute:**

1. **Deploy & Test**
   ```bash
   # Follow the Quick Start guide
   git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
   cd Wazuh-MCP-Server
   python deploy.py
   ```

2. **Report Findings**
   - Open an [Issue](https://github.com/gensecaihq/Wazuh-MCP-Server/issues) for bugs or problems
   - Share successful deployment stories
   - Suggest improvements or missing features
   - Report compatibility issues

3. **What to Report**
   - Deployment environment (OS, Docker version, Wazuh version)
   - Steps followed
   - What worked / what didn't
   - Error messages or logs
   - Performance observations
   - Integration results with Claude Desktop

**We Value:**
- Detailed bug reports with reproduction steps
- Real-world use case feedback
- Performance benchmarks
- Security findings
- Documentation improvements
- Integration testing results

**Recognition:**
All contributors who provide valuable feedback will be acknowledged in the project!

📧 **Questions?** Open a [Discussion](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions) or file an [Issue](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)

---

## 🌐 Production Features

This production-ready remote MCP server implementation includes:
- ✅ Full MCP protocol compliance (2025-06-18 specification)
- ✅ 29 specialized security tools
- ✅ Production-grade security hardening
- ✅ Enterprise deployment readiness
- ✅ Comprehensive monitoring and observability

---

## 🏆 **Summary**

The **Wazuh MCP Remote Server** represents a **gold standard implementation** of Anthropic's MCP remote server specifications:

### ✅ **What Makes This Special**

🎯 **100% MCP Compliant** - Perfect compliance score (33/33 requirements)
⚡ **Streamable HTTP & Legacy SSE** - Latest `/mcp` endpoint plus backward-compatible `/sse`
🔐 **Enterprise Security** - JWT authentication, rate limiting, CORS protection
🛡️ **Production Ready** - Docker containerized, multi-platform, health monitoring
🔧 **29 Security Tools** - Comprehensive Wazuh SIEM integration
📊 **Observable** - Prometheus metrics, structured logging, health checks  

### 🚀 **Ready for Production**

This implementation is **immediately deployable** in production environments and provides:

- ✅ **Seamless Claude Desktop integration**
- ✅ **Enterprise-grade security and reliability** 
- ✅ **Scalable container-native architecture**
- ✅ **Comprehensive monitoring and observability**
- ✅ **Full compliance with MCP protocol standards**

**The result is a robust, secure, and highly capable MCP remote server that sets the standard for enterprise AI-SIEM integrations.**
