# Wazuh MCP Server v3.0.0 Release Notes

## 🎉 Major Release: Remote MCP Server & Docker Deployment

**Release Date**: July 15, 2025  
**Version**: 3.0.0  
**Codename**: Remote Edge  

We're excited to announce Wazuh MCP Server v3.0.0, a major release that transforms the server from a local-only implementation to a production-ready remote MCP server with Docker deployment capabilities.

## 🚀 Headline Features

### Remote MCP Server
Transform your Wazuh security monitoring with **Remote MCP** capability:
- **Claude Code Integration**: Native support for remote MCP connections
- **HTTP/SSE Transport**: Real-time Server-Sent Events for live monitoring
- **Production API**: RESTful endpoints with comprehensive error handling
- **Multi-Platform**: Works across Windows, macOS, and Linux

### Enterprise Security
Industry-standard security with **OAuth 2.0** authentication:
- **JWT Token Management**: Secure, stateless authentication
- **Scope-Based Access**: Granular permission controls
- **Rate Limiting**: Protection against abuse and attacks
- **SSL/TLS**: End-to-end encryption support

### Docker Production Deployment
**Production-ready** containerization:
- **Multi-stage Build**: Optimized for security and size
- **Complete Stack**: Includes monitoring, caching, and visualization
- **Health Monitoring**: Comprehensive health checks and auto-recovery
- **Security Hardening**: Non-root execution, read-only filesystem

## 📊 Performance Improvements

- **95%+ Test Coverage**: Comprehensive testing across all components
- **< 5 Second Startup**: Fast container initialization
- **1000+ Concurrent Connections**: High-performance transport layer  
- **< 200ms Response Time**: Optimized for real-time monitoring
- **< 512MB Memory**: Efficient resource utilization

## 🔄 Migration & Compatibility

### Backward Compatibility ✅
- **All v2.0.0 Tools**: Continue to work unchanged
- **Existing Configuration**: .env files compatible
- **Stdio Transport**: Remains available for local use
- **Gradual Migration**: Deploy remote server alongside existing setup

### Upgrade Path
1. **Zero Downtime**: Deploy v3.0.0 in parallel
2. **Test Remote Access**: Validate OAuth2 integration
3. **Switch Clients**: Update Claude Code configuration
4. **Decommission Local**: Remove local server when ready

## 🛠️ Quick Start

### Docker Compose (Recommended)
```bash
# Get the latest release
git clone https://github.com/wazuh-mcp-server/wazuh-mcp-server.git
cd wazuh-mcp-server

# Configure environment
cp .env.example .env
# Edit .env with your Wazuh credentials

# Deploy complete stack
docker-compose up -d

# Access services
# - MCP Server: https://localhost:8443
# - Prometheus: http://localhost:9091  
# - Grafana: http://localhost:3000
```

### Claude Code Configuration
```json
{
  "type": "url",
  "url": "https://your-server:8443/sse",
  "name": "wazuh-remote",
  "authorization": {
    "type": "oauth2",
    "authorization_url": "https://your-server:8443/oauth/authorize",
    "token_url": "https://your-server:8443/oauth/token",
    "client_id": "wazuh-mcp-client"
  }
}
```

## 🔐 Security Enhancements

### OAuth 2.0 Implementation
- **Authorization Code Flow**: Industry-standard authentication
- **JWT Tokens**: Secure, stateless session management
- **Client Management**: OAuth2 client registration and validation
- **Scope-Based Access**: Fine-grained permission controls

### Security Hardening
- **Security Headers**: HSTS, CSP, X-Frame-Options
- **Rate Limiting**: Per-client request throttling
- **Input Validation**: Comprehensive sanitization
- **Audit Logging**: Security event tracking

### Docker Security
- **Non-root User**: Container runs as unprivileged user
- **Read-only Filesystem**: Immutable container runtime
- **Capability Dropping**: Minimal Linux capabilities
- **Security Scanning**: Vulnerability detection in CI/CD

## 📈 Monitoring & Observability

### Prometheus Metrics
- **Server Metrics**: Request rate, latency, errors
- **Authentication**: Login attempts, token usage
- **Transport**: Connection counts, message queue size
- **System**: CPU, memory, disk usage

### Structured Logging
- **JSON Format**: Machine-readable log entries
- **Correlation IDs**: Request tracing across components
- **Security Events**: Authentication and authorization logs
- **Performance**: Response times and resource usage

### Grafana Dashboards
- **Server Overview**: High-level system status
- **Performance**: Response times and throughput
- **Security**: Authentication events and threats
- **Infrastructure**: Resource utilization and health

## 🏗️ Architecture Overview

### Transport Layer
```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  Claude Code    │────▶│  Load Balancer  │────▶│  MCP Server     │
│  Remote MCP     │     │  (HTTPS/SSE)    │     │  (Container)    │
└─────────────────┘     └─────────────────┘     └─────────────────┘
                                                         │
                                                         ▼
                                                 ┌─────────────────┐
                                                 │   Wazuh API     │
                                                 └─────────────────┘
```

### Container Stack
```
┌─────────────────────────────────────────────────────────────┐
│                    Docker Compose Stack                     │
├─────────────────┬─────────────────┬─────────────────────────┤
│  MCP Server     │     Redis       │       Prometheus        │
│  (Port 8443)    │   (Caching)     │      (Metrics)          │
├─────────────────┼─────────────────┼─────────────────────────┤
│    Grafana      │   Load Balancer │     Health Checks       │
│ (Visualization) │   (Optional)    │    (Auto-recovery)      │
└─────────────────┴─────────────────┴─────────────────────────┘
```

## 🧪 Testing & Quality

### Test Coverage
- **95%+ Code Coverage**: Comprehensive test suite
- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end functionality
- **Docker Tests**: Container deployment validation
- **Security Tests**: Authentication and authorization

### Quality Assurance
- **Static Analysis**: Code quality and security scanning
- **Performance Testing**: Load testing and benchmarking
- **Security Scanning**: Vulnerability detection
- **Compliance Testing**: Authentication standards validation

## 📦 What's Included

### Core Components
- **Remote MCP Server**: HTTP/SSE transport implementation
- **OAuth 2.0 Server**: Complete authentication system
- **Transport Layer**: Multi-protocol support (stdio, HTTP, SSE)
- **Docker Stack**: Production deployment configuration

### Monitoring Stack
- **Prometheus**: Metrics collection and alerting
- **Grafana**: Visualization and dashboards
- **Redis**: Caching and session storage
- **Health Checks**: Service monitoring and recovery

### Development Tools
- **Comprehensive Tests**: 95%+ coverage test suite
- **Development Scripts**: Local development automation
- **Code Quality**: Linting, formatting, and security scanning
- **Documentation**: Complete setup and deployment guides

## 🚨 Breaking Changes

### None! 🎉
This release maintains **100% backward compatibility** with v2.0.0:
- All existing tools continue to work unchanged
- Configuration files remain compatible
- Stdio transport is preserved for local use
- Migration is optional and can be gradual

## 🔧 Configuration Changes

### New Environment Variables
```bash
# OAuth 2.0 Authentication
JWT_SECRET_KEY=your-secure-secret-key
OAUTH_CLIENT_ID=wazuh-mcp-client
OAUTH_CLIENT_SECRET=secure-client-secret

# Remote Server Configuration  
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8443
MCP_TRANSPORT=sse

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090
```

### Docker Configuration
```yaml
# docker-compose.yml additions
services:
  redis:
    image: redis:7-alpine
  prometheus:
    image: prom/prometheus:latest
  grafana:
    image: grafana/grafana:latest
```

## 🐛 Bug Fixes

- **Import Paths**: Fixed inconsistent import paths in test files (16 files)
- **Dependencies**: Resolved version conflicts in requirements
- **Configuration**: Enhanced validation and error handling
- **Transport**: Improved connection lifecycle management
- **Authentication**: Fixed edge cases in token validation

## 🚀 Performance Optimizations

- **Connection Pooling**: Reuse HTTP connections for better performance
- **Caching**: LRU cache with TTL for frequently accessed data
- **Async I/O**: Non-blocking operations throughout the stack
- **Message Batching**: Bulk operations for improved throughput
- **Container Optimization**: Multi-stage build for smaller images

## 📖 Documentation Updates

### New Documentation
- **v3.0.0 README**: Complete setup and deployment guide
- **Migration Guide**: Step-by-step upgrade instructions
- **Docker Guide**: Production deployment best practices
- **Security Guide**: Authentication and security configuration
- **API Documentation**: Interactive OpenAPI documentation

### Updated Documentation
- **Installation Guide**: Updated for remote server deployment
- **Configuration Reference**: New environment variables and options
- **Troubleshooting**: Docker and remote access issues
- **Contributing Guide**: Development setup for v3.0.0

## 🤝 Contributing

We welcome contributions! See our [Contributing Guide](docs/development/CONTRIBUTING.md) for:
- Development environment setup
- Code quality standards
- Testing requirements
- Security guidelines

## 🆘 Support

### Getting Help
- **Documentation**: https://docs.wazuh-mcp-server.org
- **Issues**: https://github.com/wazuh-mcp-server/wazuh-mcp-server/issues
- **Discussions**: https://github.com/wazuh-mcp-server/wazuh-mcp-server/discussions

### Enterprise Support
- **Professional Services**: Available for enterprise deployments
- **Custom Integration**: Tailored solutions for specific requirements
- **Training**: On-site training and workshops

## 🔮 What's Next

### v3.1.0 (Planned for Q3 2025)
- **WebSocket Transport**: Additional transport option
- **SAML Integration**: Enterprise SSO support
- **Multi-tenancy**: Isolated environments for different teams
- **Advanced Caching**: Distributed caching with Redis Cluster

### v4.0.0 (Planned for Q4 2025)
- **gRPC Transport**: High-performance binary protocol
- **Kubernetes Operator**: Native Kubernetes deployment
- **Advanced Analytics**: AI-powered threat detection
- **Federation**: Multi-cluster Wazuh support

## 🙏 Acknowledgments

Special thanks to:
- **Wazuh Community**: For valuable feedback and testing
- **Claude Code Team**: For remote MCP specification and support
- **Security Researchers**: For vulnerability reports and fixes
- **Contributors**: For code, documentation, and testing contributions

## 📜 License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

---

**Download**: [GitHub Releases](https://github.com/wazuh-mcp-server/wazuh-mcp-server/releases/tag/v3.0.0)  
**Docker**: `docker pull wazuh-mcp-server:3.0.0`  
**Documentation**: [docs.wazuh-mcp-server.org](https://docs.wazuh-mcp-server.org)

**Happy Monitoring! 🚀**