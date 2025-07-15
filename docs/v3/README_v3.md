# Wazuh MCP Server v3.0.0 - Remote MCP Server

## 🚀 Major Release: Remote MCP Capability

Wazuh MCP Server v3.0.0 introduces **Remote MCP** functionality, transforming the server from a local-only stdio implementation to a production-ready remote server accessible via HTTP/SSE. This enables integration with Claude Code's remote MCP capabilities and the MCP Connector API.

## 🆕 What's New in v3.0.0

### Remote MCP Support
- **HTTP/SSE Transport**: Server-Sent Events for real-time communication
- **OAuth 2.0 Authentication**: Production-grade security with JWT tokens
- **RESTful API**: Standard HTTP endpoints for MCP operations
- **Claude Code Integration**: Native support for remote MCP connections

### Docker Production Deployment
- **Multi-stage Dockerfile**: Optimized for production with minimal attack surface
- **Docker Compose**: Complete stack with monitoring and caching
- **Health Checks**: Comprehensive health monitoring and auto-recovery
- **Security Hardening**: Non-root user, read-only filesystem, capability dropping

### Enterprise Features
- **Monitoring & Metrics**: Prometheus integration with Grafana dashboards
- **Structured Logging**: JSON logs with correlation IDs and audit trails
- **Rate Limiting**: Per-client rate limiting with configurable thresholds
- **SSL/TLS Support**: Full HTTPS support with certificate management

## 📋 Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# Clone the repository
git clone https://github.com/wazuh-mcp-server/wazuh-mcp-server.git
cd wazuh-mcp-server

# Create environment configuration
cat > .env << EOF
WAZUH_API_URL=https://your-wazuh-manager:55000
WAZUH_API_USERNAME=your_username
WAZUH_API_PASSWORD=your_password
JWT_SECRET_KEY=$(openssl rand -base64 32)
OAUTH_CLIENT_ID=wazuh-mcp-client
OAUTH_CLIENT_SECRET=$(openssl rand -base64 32)
EOF

# Start the complete stack
docker-compose up -d

# Check service status
docker-compose ps
```

### Option 2: Direct Docker Run

```bash
# Build the image
docker build -t wazuh-mcp-server:3.0.0 .

# Run the container
docker run -d \
  --name wazuh-mcp-server \
  -p 8443:8443 \
  -p 9090:9090 \
  -e WAZUH_API_URL=https://your-wazuh-manager:55000 \
  -e WAZUH_API_USERNAME=your_username \
  -e WAZUH_API_PASSWORD=your_password \
  -e JWT_SECRET_KEY=your_jwt_secret \
  -v $(pwd)/config:/app/config:ro \
  -v $(pwd)/logs:/app/logs:rw \
  wazuh-mcp-server:3.0.0
```

### Option 3: Local Development

```bash
# Install dependencies
pip install -r requirements-v3.txt

# Set environment variables
export WAZUH_API_URL=https://your-wazuh-manager:55000
export WAZUH_API_USERNAME=your_username
export WAZUH_API_PASSWORD=your_password
export JWT_SECRET_KEY=your_jwt_secret

# Start the remote server
python -m wazuh_mcp_server.remote_server \
  --host 0.0.0.0 \
  --port 8443 \
  --transport sse \
  --log-level INFO
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `WAZUH_API_URL` | Wazuh API endpoint | - | Yes |
| `WAZUH_API_USERNAME` | Wazuh API username | - | Yes |
| `WAZUH_API_PASSWORD` | Wazuh API password | - | Yes |
| `JWT_SECRET_KEY` | JWT signing secret | - | Yes |
| `MCP_SERVER_HOST` | Server bind address | `0.0.0.0` | No |
| `MCP_SERVER_PORT` | Server bind port | `8443` | No |
| `MCP_TRANSPORT` | Transport protocol | `sse` | No |
| `OAUTH_CLIENT_ID` | OAuth client ID | `wazuh-mcp-client` | No |
| `OAUTH_CLIENT_SECRET` | OAuth client secret | - | No |
| `LOG_LEVEL` | Logging level | `INFO` | No |
| `ENABLE_METRICS` | Enable metrics endpoint | `true` | No |

### Configuration Files

Create `/app/config/server.env` for container deployment:

```bash
# Server Configuration
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8443
MCP_TRANSPORT=sse

# Wazuh Integration
WAZUH_API_URL=https://wazuh-manager:55000
WAZUH_API_USERNAME=wazuh-api
WAZUH_API_PASSWORD=SecurePassword123!
WAZUH_API_VERIFY_SSL=true

# Authentication
OAUTH_ENABLED=true
JWT_SECRET_KEY=your-256-bit-secret-key
OAUTH_CLIENT_ID=wazuh-mcp-client
OAUTH_CLIENT_SECRET=secure-client-secret

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090
```

## 🔐 Authentication & Security

### OAuth 2.0 Flow

1. **Client Registration**: Register your client with the server
2. **Authorization**: Request authorization code from `/oauth/authorize`
3. **Token Exchange**: Exchange code for access token at `/oauth/token`
4. **API Access**: Use Bearer token for authenticated requests

### API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/sse` | GET | Server-Sent Events for MCP communication |
| `/oauth/authorize` | GET | OAuth2 authorization endpoint |
| `/oauth/token` | POST | OAuth2 token endpoint |
| `/health` | GET | Health check endpoint |
| `/metrics` | GET | Prometheus metrics |
| `/info` | GET | Server information |
| `/docs` | GET | API documentation |

### Security Features

- **OAuth 2.0**: Industry-standard authentication
- **JWT Tokens**: Secure, stateless authentication
- **Rate Limiting**: Protection against abuse
- **HTTPS Only**: Encrypted communications
- **CORS Protection**: Cross-origin request security
- **Security Headers**: Comprehensive HTTP security headers

## 📊 Monitoring & Observability

### Health Checks

```bash
# Check server health
curl -f http://localhost:8443/health

# Response
{
  "status": "healthy",
  "version": "3.0.0",
  "uptime": 3600,
  "transport": "sse",
  "requests_processed": 1234,
  "timestamp": 1640995200
}
```

### Metrics

```bash
# Get Prometheus metrics
curl http://localhost:9090/metrics

# Get detailed metrics
curl http://localhost:8443/metrics
```

### Logging

Structured JSON logs with:
- Request correlation IDs
- Security event tracking
- Performance metrics
- Error context

## 🔌 Claude Code Integration

### Remote MCP Configuration

Add to your Claude Code configuration:

```json
{
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
```

### Available Scopes

| Scope | Description |
|-------|-------------|
| `read:alerts` | Read Wazuh alerts |
| `read:agents` | Read agent information |
| `read:vulnerabilities` | Read vulnerability data |
| `read:stats` | Read statistics |
| `read:logs` | Read log data |
| `write:agents` | Modify agent configurations |
| `admin:cluster` | Cluster administration |
| `admin:config` | Configuration management |

## 🏗️ Architecture

### Transport Layer

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Claude Code    │────▶│  Load Balancer  │────▶│  MCP Server     │
│  Remote MCP     │     │  (HTTPS/SSE)    │     │  (Docker)       │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                         │
                                                         ▼
                                                 ┌─────────────────┐
                                                 │   Wazuh API     │
                                                 └─────────────────┘
```

### Component Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Remote MCP Server                        │
├─────────────────────────────────────────────────────────────┤
│  HTTP/SSE Transport  │  OAuth2 Auth  │  Rate Limiting      │
├─────────────────────────────────────────────────────────────┤
│  Transport Adapter   │  JWT Manager  │  Security Headers   │
├─────────────────────────────────────────────────────────────┤
│  MCP Core Server     │  Tool Factory │  Error Handling     │
├─────────────────────────────────────────────────────────────┤
│  Wazuh API Client    │  Field Mapper │  Caching Layer      │
└─────────────────────────────────────────────────────────────┘
```

## 🧪 Testing

### Run Tests

```bash
# Install test dependencies
pip install -r requirements-v3.txt

# Run all tests
python -m pytest tests/v3/

# Run specific test categories
python -m pytest tests/v3/test_transport_layer.py
python -m pytest tests/v3/test_oauth2_auth.py
python -m pytest tests/v3/test_remote_server.py

# Run Docker integration tests
python -m pytest tests/v3/test_docker_integration.py -m docker
```

### Test Categories

- **Transport Layer**: HTTP/SSE transport functionality
- **Authentication**: OAuth2 and JWT token management
- **Remote Server**: End-to-end server functionality
- **Docker Integration**: Container deployment and health

## 📈 Performance

### Benchmarks

- **Startup Time**: < 5 seconds
- **Memory Usage**: < 512MB under normal load
- **Response Time**: < 200ms (p95)
- **Concurrent Connections**: 1000+ supported
- **Request Rate**: 10,000+ requests/minute

### Optimization Features

- **Connection Pooling**: Reuse HTTP connections
- **Caching**: LRU cache with TTL
- **Async I/O**: Non-blocking operations
- **Request Batching**: Bulk operations support

## 🔄 Migration from v2.0.0

### Backward Compatibility

- All v2.0.0 tools continue to work unchanged
- Existing configuration files are compatible
- Stdio transport remains available for local use

### Migration Steps

1. **Update Dependencies**: Install v3.0.0 requirements
2. **Configure Authentication**: Set up OAuth2 credentials
3. **Deploy Remote Server**: Use Docker or direct deployment
4. **Update Clients**: Configure for remote MCP access

### Migration Script

```bash
# Run the migration script
./scripts/migrate_v2_to_v3.sh

# Or manually update configuration
cp .env.example .env
# Edit .env with your settings
```

## 🛠️ Development

### Local Development Setup

```bash
# Clone and setup
git clone https://github.com/wazuh-mcp-server/wazuh-mcp-server.git
cd wazuh-mcp-server

# Create virtual environment
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows

# Install dependencies
pip install -r requirements-v3.txt
pip install -r requirements-dev.txt

# Run tests
pytest tests/v3/

# Start development server
python -m wazuh_mcp_server.remote_server --log-level DEBUG
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint code
flake8 src/ tests/

# Type checking
mypy src/

# Security scanning
bandit -r src/
```

## 📚 API Documentation

### Interactive Documentation

Visit `http://localhost:8443/docs` for interactive API documentation.

### OpenAPI Specification

Download the OpenAPI spec from `http://localhost:8443/openapi.json`.

## 🆘 Troubleshooting

### Common Issues

1. **Connection Refused**: Check firewall and port binding
2. **Authentication Errors**: Verify OAuth2 configuration
3. **SSL Issues**: Ensure certificate validity
4. **Memory Issues**: Increase container memory limits

### Debug Mode

```bash
# Enable debug logging
export LOG_LEVEL=DEBUG
python -m wazuh_mcp_server.remote_server --log-level DEBUG

# Check container logs
docker-compose logs -f wazuh-mcp-server
```

### Health Check

```bash
# Check all services
curl -f http://localhost:8443/health
curl -f http://localhost:9090/metrics
curl -f http://localhost:3000  # Grafana
```

## 🤝 Contributing

See [CONTRIBUTING.md](../development/CONTRIBUTING.md) for development guidelines.

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](../../LICENSE) file for details.

## 🔗 Links

- [GitHub Repository](https://github.com/wazuh-mcp-server/wazuh-mcp-server)
- [Docker Hub](https://hub.docker.com/r/wazuh-mcp-server/wazuh-mcp-server)
- [Documentation](https://docs.wazuh-mcp-server.org)
- [Issue Tracker](https://github.com/wazuh-mcp-server/wazuh-mcp-server/issues)