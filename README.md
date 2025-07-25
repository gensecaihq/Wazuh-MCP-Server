# Wazuh MCP Server - Production-Ready Security Operations Platform

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![FastMCP](https://img.shields.io/badge/FastMCP-2.10.6-green.svg)](https://github.com/anthropics/fastmcp)
[![Wazuh Compatible](https://img.shields.io/badge/Wazuh-4.8%2B-orange.svg)](https://wazuh.com/)
[![Production Ready](https://img.shields.io/badge/Status-Production%20Ready-green.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server)
[![Security Audited](https://img.shields.io/badge/Security-Audited-blue.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server)

A **production-grade FastMCP-powered server** that provides AI-enhanced security operations through Wazuh SIEM integration. Supports both STDIO (Claude Desktop) and HTTP/SSE (remote access) transports with comprehensive Docker deployment.

## 🌟 Key Features

- **🔄 Dual Transport Support**: STDIO for Claude Desktop + HTTP/SSE for remote access
- **🏗️ Distributed Architecture**: Full support for Wazuh Server + Indexer separation
- **🐳 Enterprise Docker**: Production-ready containerization with security hardening
- **🛡️ Security-First**: SSL/TLS, rate limiting, input validation, and audit logging
- **⚡ High Performance**: Optimized connection pooling, caching, and async operations
- **🔍 AI-Powered Analysis**: Advanced threat detection with Claude integration
- **📊 Comprehensive Monitoring**: Health checks, metrics, and structured logging
- **🎯 Zero Configuration**: Smart defaults with extensive customization options

<img width="797" height="568" alt="claude0mcp-wazuh" src="https://github.com/user-attachments/assets/458d3c94-e1f9-4143-a1a4-85cb629287d4" />

---

## 📋 Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Usage](#usage)
- [Advanced Configuration](#advanced-configuration)
- [Troubleshooting](#troubleshooting)
- [Security](#security)
- [Contributing](#contributing)

---

## 🔧 Prerequisites

### System Requirements
- **Docker**: 20.10+ (required)
- **Docker Compose**: 2.0+ (required for compose deployment)
- **Operating System**: Any Docker-compatible OS (Linux, macOS, Windows)

### Wazuh Infrastructure
- **Wazuh Server**: 4.0+ (required)
- **Wazuh Indexer**: 4.8+ (optional, for enhanced features)
- **Network Access**: HTTPS connectivity to Wazuh components

### Claude Integration
- **Claude Desktop**: Latest version (for STDIO mode)
- **API Access**: For HTTP/SSE mode integration

---

## 🚀 Installation

### Method 1: Docker Deployment (Recommended)

#### Step 1: Clone Repository
```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
```

#### Step 2: Choose Configuration Template

**For Single Wazuh Server:**
```bash
cp .env.docker.template .env
```

**For Distributed Setup (Server + Indexer):**
```bash
cp .env.production .env
```

#### Step 3: Configure Environment
Edit `.env` with your Wazuh details:

```bash
# Required: Wazuh Server Configuration
WAZUH_HOST=your-wazuh-server.com
WAZUH_USER=your-api-user  
WAZUH_PASS=your-secure-password

# Optional: Distributed Wazuh Indexer (if separate)
WAZUH_INDEXER_HOST=your-indexer-server.com
WAZUH_INDEXER_USER=indexer-user
WAZUH_INDEXER_PASS=indexer-password

# Transport Mode
MCP_TRANSPORT=stdio  # or 'http' for remote access
```

#### Step 4: Build and Deploy
```bash
# Build production image
docker build -t wazuh-mcp-server:latest .

# Deploy with Docker Compose (recommended)
docker compose up -d

# Or run directly
docker run -d --name wazuh-mcp \
  --env-file .env \
  --restart unless-stopped \
  wazuh-mcp-server:latest
```

#### Step 5: Verify Deployment
```bash
# Check container status
docker compose ps

# View logs
docker compose logs wazuh-mcp-server

# Test health check
docker exec wazuh-mcp python3 validate-production.py --quick
```

### Method 2: Local Development Installation

#### Step 1: Setup Python Environment
```bash
# Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

#### Step 2: Configure Environment
```bash
# Copy configuration template
cp .env.production .env

# Edit .env with your Wazuh configuration
nano .env
```

#### Step 3: Validate Installation
```bash
# Run production validation
python3 validate-production.py

# Test server startup
./wazuh-mcp-server --help
```

---

## ⚙️ Configuration

### Basic Configuration

The minimum required configuration in `.env`:

```bash
# Wazuh Server (Required)
WAZUH_HOST=wazuh.company.com
WAZUH_USER=mcp-api-user
WAZUH_PASS=secure-password-123

# Transport Mode
MCP_TRANSPORT=stdio  # 'stdio' for Claude Desktop, 'http' for remote
```

### Distributed Wazuh Setup

For Wazuh deployments with separate Server and Indexer:

```bash
# Wazuh Server
WAZUH_HOST=wazuh-server.company.com
WAZUH_PORT=55000
WAZUH_USER=server-api-user
WAZUH_PASS=server-password

# Wazuh Indexer (separate server)
WAZUH_INDEXER_HOST=wazuh-indexer.company.com
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=indexer-user
WAZUH_INDEXER_PASS=indexer-password

# Enable Indexer features
USE_INDEXER_FOR_ALERTS=true
USE_INDEXER_FOR_VULNERABILITIES=true
```

### Security Configuration

```bash
# SSL/TLS Settings
VERIFY_SSL=true
ALLOW_SELF_SIGNED=false
SSL_TIMEOUT=30

# Performance Tuning
MAX_ALERTS_PER_QUERY=1000
MAX_CONNECTIONS=25
REQUEST_TIMEOUT_SECONDS=30

# Rate Limiting
MAX_REQUESTS_PER_MINUTE=100
BURST_REQUEST_SIZE=20
```

### HTTP Transport Configuration

For remote access deployments:

```bash
# HTTP Transport Settings
MCP_TRANSPORT=http
MCP_HOST=0.0.0.0
MCP_PORT=3000

# CORS Settings (if needed)
MCP_CORS_ORIGINS=["https://your-domain.com"]
```

---

## 🚀 Deployment

### Production Docker Deployment

#### Single Server Deployment
```bash
# Create production environment
cp .env.docker.template .env

# Edit configuration
nano .env

# Deploy with restart policy
docker run -d \
  --name wazuh-mcp-production \
  --restart unless-stopped \
  --env-file .env \
  --health-cmd="python3 validate-production.py --quick" \
  --health-interval=30s \
  --health-timeout=10s \
  --health-retries=3 \
  wazuh-mcp-server:latest
```

#### High Availability Deployment
```bash
# Use Docker Compose for production
cat > docker-compose.prod.yml << EOF
version: '3.8'
services:
  wazuh-mcp-server:
    image: wazuh-mcp-server:latest
    container_name: wazuh-mcp-production
    restart: unless-stopped
    env_file: .env
    ports:
      - "3000:3000"  # Only for HTTP transport
    healthcheck:
      test: ["CMD", "python3", "validate-production.py", "--quick"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - wazuh-network
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'

networks:
  wazuh-network:
    driver: bridge
EOF

# Deploy
docker compose -f docker-compose.prod.yml up -d
```

#### Enterprise Deployment with Monitoring
```bash
# Extended production compose with monitoring
cat > docker-compose.enterprise.yml << EOF
version: '3.8'
services:
  wazuh-mcp-server:
    image: wazuh-mcp-server:latest
    container_name: wazuh-mcp-enterprise
    restart: unless-stopped
    env_file: .env
    environment:
      - ENABLE_METRICS=true
      - STRUCTURED_LOGGING=true
      - LOG_LEVEL=INFO
    ports:
      - "3000:3000"
    volumes:
      - ./logs:/app/logs
      - ./config:/app/config:ro
    healthcheck:
      test: ["CMD", "python3", "validate-production.py", "--quick"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - wazuh-network
    deploy:
      replicas: 2
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3

networks:
  wazuh-network:
    driver: bridge
EOF

# Deploy enterprise stack
docker compose -f docker-compose.enterprise.yml up -d
```

### Deployment Verification

```bash
# Check deployment status
docker compose ps

# Verify health checks
docker compose exec wazuh-mcp-server python3 validate-production.py

# Test connectivity
docker compose exec wazuh-mcp-server python3 -c "
from wazuh_mcp_server.config import WazuhConfig
config = WazuhConfig.from_env()
print(f'Connected to Wazuh: {config.host}:{config.port}')
"

# Monitor logs
docker compose logs -f wazuh-mcp-server
```

---

## 📖 Usage

### Claude Desktop Integration (STDIO Mode)

1. **Start the MCP Server**:
```bash
# Local installation
./wazuh-mcp-server

# Docker deployment
docker run --env-file .env wazuh-mcp-server:latest
```

2. **Configure Claude Desktop**:

Add to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/wazuh-mcp-server",
      "args": ["--stdio"],
      "env": {
        "WAZUH_HOST": "your-wazuh-server.com",
        "WAZUH_USER": "your-api-user",
        "WAZUH_PASS": "your-password"
      }
    }
  }
}
```

3. **Restart Claude Desktop** and start using Wazuh tools!

### HTTP/SSE Mode (Remote Access)

1. **Start HTTP Server**:
```bash
# Local
./wazuh-mcp-server --http

# Docker
docker run -p 3000:3000 --env-file .env wazuh-mcp-server:latest --http
```

2. **Access via HTTP**:
```bash
# Test server health
curl http://localhost:3000/health

# Connect with MCP client
# (Refer to MCP HTTP transport documentation)
```

### Available Tools

Once connected, you can use these Wazuh tools:

#### 🔍 **Security Analysis**
```
Get recent security alerts with AI analysis
```

#### 📊 **Agent Health Monitoring**
```  
Check Wazuh agent status and health metrics
```

#### 🎯 **Threat Detection**
```
Analyze security threats with AI-powered insights
```

#### 📈 **Server Health**
```
Monitor MCP server performance and connectivity
```

### Example Usage in Claude

```
Human: Show me the latest security alerts from Wazuh

Claude: I'll retrieve the latest security alerts from your Wazuh server and provide an analysis.

[Uses get_wazuh_alerts tool]

Based on the latest alerts from your Wazuh server, I found:

🚨 **Critical Alerts (3)**
- Failed login attempts from 192.168.1.100
- Malware detection on Agent 001  
- Suspicious network traffic on Agent 005

📊 **Alert Summary**
- Total alerts: 15
- High severity: 3
- Medium severity: 8
- Low severity: 4

🔍 **AI Analysis**
The failed login attempts suggest a potential brute force attack. I recommend:
1. Blocking IP 192.168.1.100
2. Investigating Agent 001 for malware cleanup
3. Network traffic analysis for Agent 005
```

---

## 🔧 Advanced Configuration

### Environment Variables Reference

#### **Wazuh Server Configuration**
| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_HOST` | - | Wazuh server hostname/IP (required) |
| `WAZUH_PORT` | 55000 | Wazuh API port |
| `WAZUH_USER` | - | API username (required) |
| `WAZUH_PASS` | - | API password (required) |
| `WAZUH_API_VERSION` | v4 | API version |

#### **Wazuh Indexer Configuration**
| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_INDEXER_HOST` | Same as WAZUH_HOST | Indexer hostname |
| `WAZUH_INDEXER_PORT` | 9200 | Indexer port |
| `WAZUH_INDEXER_USER` | Same as WAZUH_USER | Indexer username |
| `WAZUH_INDEXER_PASS` | Same as WAZUH_PASS | Indexer password |
| `USE_INDEXER_FOR_ALERTS` | true | Use Indexer for alerts |
| `USE_INDEXER_FOR_VULNERABILITIES` | true | Use Indexer for vulnerabilities |

#### **Transport Configuration**
| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_TRANSPORT` | stdio | Transport mode (stdio/http) |
| `MCP_HOST` | localhost | HTTP server host |
| `MCP_PORT` | 3000 | HTTP server port |

#### **Performance Settings**
| Variable | Default | Description |
|----------|---------|-------------|
| `MAX_ALERTS_PER_QUERY` | 1000 | Maximum alerts per request |
| `MAX_CONNECTIONS` | 25 | Connection pool size |
| `REQUEST_TIMEOUT_SECONDS` | 30 | Request timeout |
| `CACHE_TTL_SECONDS` | 300 | Cache lifetime |

#### **Security Settings**
| Variable | Default | Description |
|----------|---------|-------------|
| `VERIFY_SSL` | true | SSL certificate verification |
| `ALLOW_SELF_SIGNED` | false | Allow self-signed certificates |
| `MAX_REQUESTS_PER_MINUTE` | 100 | Rate limiting |
| `SSL_TIMEOUT` | 30 | SSL connection timeout |

### Custom SSL Configuration

For environments with custom certificates:

```bash
# Custom CA bundle
CA_BUNDLE_PATH=/path/to/custom-ca.pem

# Client certificates
CLIENT_CERT_PATH=/path/to/client.crt
CLIENT_KEY_PATH=/path/to/client.key

# Indexer SSL (if different)
WAZUH_INDEXER_VERIFY_SSL=true
INDEXER_CA_BUNDLE_PATH=/path/to/indexer-ca.pem
```

### Logging Configuration

```bash
# Logging levels
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL
STRUCTURED_LOGGING=true
ENABLE_LOG_ROTATION=true

# Log files (optional)
LOG_DIR=/var/log/wazuh-mcp-server
MAX_LOG_SIZE_MB=10
LOG_BACKUP_COUNT=5
```

### External API Integration

```bash
# Optional threat intelligence APIs
VIRUSTOTAL_API_KEY=your-virustotal-key
SHODAN_API_KEY=your-shodan-key
ABUSEIPDB_API_KEY=your-abuseipdb-key

# Enable external features
ENABLE_EXTERNAL_INTEL=true
ENABLE_ML_ANALYSIS=true
ENABLE_COMPLIANCE_CHECKING=true
```

---

## 🔍 Troubleshooting

### Common Issues

#### 1. Connection Failed to Wazuh
```bash
# Test connectivity
docker exec wazuh-mcp curl -k https://your-wazuh-server:55000

# Check configuration
docker exec wazuh-mcp python3 validate-production.py

# Verify credentials
docker exec wazuh-mcp python3 -c "
from wazuh_mcp_server.scripts.connection_validator import ConnectionValidator
from wazuh_mcp_server.config import WazuhConfig
config = WazuhConfig.from_env()
validator = ConnectionValidator(config)
import asyncio
asyncio.run(validator.run_all_tests())
"
```

#### 2. SSL Certificate Issues
```bash
# Disable SSL verification temporarily (testing only)
echo "VERIFY_SSL=false" >> .env

# Or add custom CA bundle
echo "CA_BUNDLE_PATH=/path/to/ca.pem" >> .env
```

#### 3. Docker Container Won't Start
```bash
# Check logs
docker logs wazuh-mcp-server

# Verify environment variables
docker exec wazuh-mcp env | grep WAZUH

# Test with minimal config
docker run --rm -e WAZUH_HOST=test.com -e WAZUH_USER=test -e WAZUH_PASS=test wazuh-mcp-server:latest python3 validate-production.py --quick
```

#### 4. Performance Issues
```bash
# Increase connection limits
echo "MAX_CONNECTIONS=50" >> .env
echo "POOL_SIZE=25" >> .env

# Enable caching
echo "CACHE_TTL_SECONDS=300" >> .env

# Monitor resource usage
docker stats wazuh-mcp-server
```

### Debug Mode

Enable detailed debugging:

```bash
# Debug environment
echo "DEBUG=true" >> .env
echo "LOG_LEVEL=DEBUG" >> .env

# Restart with debug logs
docker compose restart
docker compose logs -f wazuh-mcp-server
```

### Health Checks

```bash
# Manual health check
docker exec wazuh-mcp python3 validate-production.py

# Quick validation
docker exec wazuh-mcp python3 validate-production.py --quick

# Server health endpoint (HTTP mode)
curl http://localhost:3000/health
```

---

## 🛡️ Security

### Security Best Practices

1. **Environment Variables**: Never commit `.env` files with real credentials
2. **SSL/TLS**: Always use `VERIFY_SSL=true` in production
3. **Network Security**: Use firewalls to restrict access to Wazuh servers
4. **Container Security**: Run containers with read-only filesystems when possible
5. **Regular Updates**: Keep base images and dependencies updated

### Security Features

- **Input Validation**: All inputs are validated and sanitized
- **Rate Limiting**: Configurable request rate limiting
- **SSL/TLS**: Full SSL certificate validation and custom CA support
- **Audit Logging**: Security-relevant events are logged
- **Non-Root Execution**: Container runs as non-root user
- **Resource Limits**: Memory and CPU limits prevent resource exhaustion

### Security Configuration

```bash
# Production security settings
VERIFY_SSL=true
ALLOW_SELF_SIGNED=false
MAX_REQUESTS_PER_MINUTE=100
ENABLE_HEALTH_CHECKS=true
STRUCTURED_LOGGING=true
AUTO_DETECT_SSL_ISSUES=true
```

---

## 🤝 Contributing

We welcome contributions! Please see our comprehensive documentation:

- **🧑‍💻 [Developer Guide](DEVELOPER_GUIDE.md)** - Complete developer contribution guide with architecture, coding standards, and workflows
- **🔧 [Wazuh Admin Guide](WAZUH_ADMIN_GUIDE.md)** - Production deployment and configuration for Wazuh administrators  
- **🛡️ [Security Professional Guide](SECURITY_PROFESSIONAL_GUIDE.md)** - AI-enhanced security operations and threat analysis
- **📝 [Contributing Guide](docs/development/CONTRIBUTING.md)** - Quick reference for contributors

### Development Setup

```bash
# Clone and setup development environment
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# Create development environment
python3 -m venv dev-env
source dev-env/bin/activate
pip install -r requirements.txt

# Install development dependencies
pip install pytest pytest-asyncio black ruff mypy

# Run tests
pytest tests/

# Code formatting
black src/
ruff check src/
```

### Reporting Issues

Please report issues through GitHub Issues with:
- Detailed description
- Environment details (OS, Docker version, etc.)
- Configuration (sanitized)
- Logs (sanitized)
- Steps to reproduce

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 🙏 Acknowledgments

- **Anthropic** for the FastMCP framework
- **Wazuh** for the excellent SIEM platform
- **Claude** for AI-powered security analysis
- **Community contributors** for testing and feedback

---

## 📚 Additional Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [FastMCP Documentation](https://github.com/anthropics/fastmcp)
- [Claude Desktop Configuration](https://claude.ai/docs)
- [Docker Best Practices](https://docs.docker.com/develop/best-practices/)

---

**⭐ Star this repository if you find it useful!**

For support, please open an issue on GitHub or check our [documentation](docs/).