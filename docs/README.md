# Wazuh MCP Server Documentation

Welcome to the comprehensive documentation for Wazuh MCP Server. This documentation is organized by version to help you choose and use the right version for your needs.

## 📋 Quick Navigation

### 🏷️ Version Selection
- **[v2.0.0 Documentation](#v200-current-release---local-mcp-stdio)** - Current stable release (main branch)
- **[v3.0.0 Documentation](#v300-coming-soon---remote-mcp-ssedocker)** - Coming soon preview (v3-check branch)
- **[Version Comparison](#version-comparison)** - Detailed feature comparison

### 🚀 Quick Start
- **For immediate use**: [v2.0.0 Installation Guide](user-guides/claude-desktop-setup.md)
- **For testing v3**: [v3.0.0 Preview Guide](v3/README_v3.md)

---

## v2.0.0 (Current Release) - Local MCP stdio

**Status**: ✅ **PRODUCTION READY** - Current stable release  
**Branch**: `main`  
**Architecture**: Local MCP Server with stdio transport  
**Best For**: Current production deployments, development, immediate use

### 📚 v2.0.0 Documentation

#### 🚀 Getting Started
- **[Installation Guide](user-guides/claude-desktop-setup.md)** - Complete installation instructions
- **[Configuration Guide](v2/configuration.md)** - Environment setup and tuning
- **[Quick Reference](v2/quick-reference.md)** - Essential commands and tips

#### 🔌 Integration
- **[Claude Desktop Setup](user-guides/claude-desktop-setup.md)** - Complete integration guide
- **[Platform-Specific Setup](v2/platform-guides/)** - Windows, macOS, Linux specifics
- **[API Usage Examples](v2/examples/)** - Real-world usage patterns

#### 🛠️ Troubleshooting
- **[Common Issues](v2/troubleshooting.md)** - Solutions to frequent problems
- **[Unix Troubleshooting](troubleshooting/unix-troubleshooting.md)** - macOS/Linux solutions
- **[Windows Troubleshooting](troubleshooting/windows-troubleshooting.md)** - Windows solutions

#### 🔧 Advanced Usage
- **[Development Guide](development/CONTRIBUTING.md)** - Contributing and extending
- **[Performance Tuning](v2/performance.md)** - Optimization tips
- **[Security Best Practices](v2/security.md)** - Security configuration

---

## v3.0.0 (Coming Soon) - Remote MCP SSE/Docker

**Status**: 🔜 **COMING SOON** - Advanced containerized version  
**Branch**: `v3-check`  
**Architecture**: Remote MCP Server with HTTP/SSE transport  
**Best For**: Future enterprise deployments requiring remote access and high availability

### 📚 v3.0.0 Documentation

#### 🐳 Getting Started
- **[Docker Deployment Guide](v3/README_v3.md)** - Complete Docker setup
- **[Quick Start with Docker](v3/quickstart-docker.md)** - One-command deployment
- **[Configuration Management](v3/configuration.md)** - Advanced configuration options
- **[Docker Hub Setup](DOCKER_HUB_SETUP.md)** - Published images guide

#### 🔐 Security & Enterprise
- **[Security Features](v3/security.md)** - OAuth2, encryption, monitoring
- **[Production Deployment](operations/PRODUCTION_DEPLOYMENT.md)** - Enterprise setup
- **[High Availability](v3/high-availability.md)** - HA configuration
- **[Monitoring & Alerting](v3/monitoring.md)** - Prometheus, Grafana setup

#### 🌐 Remote Access
- **[Remote MCP Setup](v3/remote-mcp.md)** - HTTP/SSE transport configuration
- **[OAuth2 Configuration](v3/oauth2.md)** - Authentication and authorization
- **[SSL/TLS Setup](v3/ssl-setup.md)** - Certificate management

#### 🔧 Operations
- **[Docker Operations](v3/docker-operations.md)** - Container management
- **[Docker Troubleshooting](troubleshooting/docker-troubleshooting.md)** - Container issues
- **[Backup & Recovery](v3/backup-recovery.md)** - Data protection
- **[Incident Response](operations/INCIDENT_RESPONSE.md)** - Security incident handling

---

## Version Comparison

| Feature | v2.0.0 (Current) | v3.0.0 (Coming Soon) |
|---------|------------------|----------------------|
| **Status** | ✅ Production Ready | 🔜 Coming Soon |
| **Transport** | stdio (local only) | HTTP/HTTPS + SSE (remote) |
| **Deployment** | Python installation | Docker containers |
| **Setup Complexity** | Simple | Single command |
| **Dependencies** | Host Python environment | All containerized |
| **Authentication** | Basic | OAuth2 + JWT |
| **Monitoring** | Basic logging | Prometheus + Grafana |
| **Scaling** | Single instance | Horizontal scaling |
| **Security** | Standard | Enterprise hardening |
| **Remote Access** | No | Yes |
| **High Availability** | No | Yes |
| **Best For** | Immediate deployment | Future enterprise needs |

---

## Migration & Planning

### 📋 Current Users (v2.0.0)
- **[v2.0.0 Production Guide](v2/production-deployment.md)** - Deploy v2 in production
- **[v2.0.0 Best Practices](v2/best-practices.md)** - Optimization and security
- **[Future Migration Planning](MIGRATION_GUIDE.md)** - Prepare for v3.0.0

### 🔮 Future Planning (v3.0.0)
- **[v3.0.0 Preview Guide](v3/README_v3.md)** - Test and evaluate v3 features
- **[Migration Strategy](v3/migration-from-v2.md)** - Plan your v3 migration
- **[Enterprise Readiness](v3/enterprise-readiness.md)** - Assess v3 benefits

---

## Common Tasks by Version

### v2.0.0 (Current Release)
```bash
# Install and setup
git checkout main
python3 scripts/install.py
cp .env.example .env
# Edit .env with your details

# Test and validate
python scripts/validate_setup.py
python scripts/test_connection.py
```

### v3.0.0 (Preview)
```bash
# Preview deployment
git checkout v3-check
cp .env.example .env
# Edit .env with your details
docker compose up -d

# Verify deployment
docker compose ps
curl -f -k https://localhost:8443/health
```

---

## Support & Resources

### 📞 Getting Help
- **[GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)** - Bug reports and feature requests
- **[GitHub Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)** - Community support
- **[Troubleshooting Guides](troubleshooting/)** - Self-service solutions

### 📖 Additional Resources
- **[Security Policy](../SECURITY.md)** - Security reporting and policies
- **[Contributing Guide](development/CONTRIBUTING.md)** - How to contribute
- **[v3 Roadmap](GITHUB_DISCUSSION_V3_ROADMAP.md)** - Future development plans

### 🏷️ Version-Specific Resources
- **v2.0.0**: [Examples](v2/examples/) | [API Docs](v2/api-reference.md) | [FAQ](v2/faq.md)
- **v3.0.0**: [Docker Hub](DOCKER_HUB_SETUP.md) | [Security Features](v3/security.md) | [Architecture](v3/architecture.md)

---

## Quick Reference Table

| Need | v2.0.0 (Traditional) | v3.0.0 (Docker) |
|------|----------------------|------------------|
| **Setup** | [Installation Guide](user-guides/claude-desktop-setup.md) | [v3 Docker Guide](v3/README_v3.md) |
| **Issues** | [Unix](troubleshooting/unix-troubleshooting.md) / [Windows](troubleshooting/windows-troubleshooting.md) | [Docker Troubleshooting](troubleshooting/docker-troubleshooting.md) |
| **Production** | [v2 Production](v2/production-deployment.md) | [Production Deployment](operations/PRODUCTION_DEPLOYMENT.md) |
| **Migration** | [Migration Guide](MIGRATION_GUIDE.md) | [Migration Guide](MIGRATION_GUIDE.md) |
| **Security** | [v2 Security](v2/security.md) | [Security Guide](security/README.md) |

---

## 📊 Documentation Status

| Section | v2.0.0 Status | v3.0.0 Status |
|---------|---------------|---------------|
| Installation | ✅ Complete | ✅ Complete |
| Configuration | ✅ Complete | ✅ Complete |
| Troubleshooting | ✅ Complete | ✅ Complete |
| Security | 🔄 In Progress | ✅ Complete |
| Examples | 📝 Planned | 🔄 In Progress |
| Advanced Topics | 📝 Planned | 🔄 In Progress |

---

*Last updated: July 16, 2025*  
*For the most current information, always refer to the branch-specific README files.*