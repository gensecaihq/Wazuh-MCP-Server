# Wazuh MCP Server v3.0.0 - Repository Structure

## Overview

This document provides a comprehensive overview of the cleaned and organized repository structure for Wazuh MCP Server v3.0.0.

## 📁 Repository Structure

```
Wazuh-MCP-Server/
├── 📄 Core Files
│   ├── README.md                     # Main documentation with v3.0.0 features
│   ├── CHANGELOG.md                  # Version history and release notes
│   ├── LICENSE                       # MIT License
│   ├── pyproject.toml               # Python package configuration
│   └── Dockerfile                   # Production-ready container image
│
├── 📄 Release Documentation
│   ├── PRODUCTION_AUDIT_v3.0.0.md  # Production readiness assessment
│   └── RELEASE_NOTES_v3.0.0.md     # v3.0.0 release notes
│
├── 🐳 Docker Configuration
│   ├── docker-compose.yml           # Basic Docker setup
│   ├── docker-compose.ha.yml       # High availability deployment
│   └── docker/
│       └── entrypoint.sh           # Container entry point
│
├── ⚙️ Configuration Files
│   ├── .env.example                 # Development configuration template
│   ├── .env.production.example     # Production configuration template
│   ├── .gitignore                  # Git ignore rules
│   ├── .dockerignore               # Docker ignore rules
│   └── .gitleaks.toml              # Security scanning configuration
│
├── 📦 Dependencies
│   ├── requirements.txt             # Core dependencies
│   ├── requirements-dev.txt        # Development dependencies
│   ├── requirements-prod.txt       # Production dependencies
│   └── requirements-v3.txt         # v3.0.0 specific dependencies
│
├── 📚 Documentation
│   ├── MIGRATION_GUIDE.md          # Version migration guide
│   ├── development/
│   │   └── CONTRIBUTING.md         # Contribution guidelines
│   ├── operations/
│   │   ├── INCIDENT_RESPONSE.md    # Emergency procedures
│   │   ├── PRODUCTION_DEPLOYMENT.md # Production setup guide
│   │   └── RUNBOOKS.md             # Operational procedures
│   ├── security/
│   │   └── README.md               # Security configuration guide
│   ├── technical/
│   │   ├── COMPREHENSIVE_AUDIT_REPORT.md
│   │   ├── PHASE_5_PROMPT_ENHANCEMENT_DETAILED_PLAN.md
│   │   ├── PRODUCTION_READINESS_AUDIT.md
│   │   └── WRAPPER_SCRIPT_DOCUMENTATION.md
│   ├── troubleshooting/
│   │   ├── docker-troubleshooting.md    # Container issues
│   │   ├── unix-troubleshooting.md      # Linux/macOS issues
│   │   └── windows-troubleshooting.md   # Windows issues
│   ├── user-guides/
│   │   └── claude-desktop-setup.md     # Claude Desktop setup
│   ├── v3/
│   │   └── README_v3.md               # v3.0.0 specific documentation
│   └── releases/
│       ├── UPCOMING.md               # Future features
│       └── V2_COMPLETION_REPORT.md   # v2.0.0 completion report
│
├── 🔧 Scripts & Tools
│   ├── install.py                   # Installation script
│   ├── install-windows.bat         # Windows installation
│   ├── validate_setup.py           # Setup validation
│   ├── validate_v3_release.py      # v3.0.0 validation
│   ├── mcp_wrapper.sh              # Unix wrapper script
│   ├── test_wrapper.sh             # Testing utilities
│   ├── migrate_v1_to_v2.sh         # Migration script
│   ├── security-scan.sh            # Security scanning
│   ├── backup-system.sh            # Backup utilities
│   ├── docker-backup.sh            # Docker backup
│   ├── deploy-ha.sh                # High availability deployment
│   ├── setup-alerting.sh           # Alerting configuration
│   └── fix_imports.py              # Import path fixes
│
├── 💻 Source Code
│   └── src/
│       └── wazuh_mcp_server/
│           ├── __init__.py
│           ├── __version__.py
│           ├── main.py              # Main application entry
│           ├── config.py            # Configuration management
│           ├── remote_server.py     # v3.0.0 remote server
│           ├── api/                 # Wazuh API integration
│           │   ├── wazuh_client.py
│           │   ├── wazuh_client_manager.py
│           │   ├── wazuh_field_mappings.py
│           │   └── wazuh_indexer_client.py
│           ├── auth/                # v3.0.0 authentication
│           │   ├── middleware.py
│           │   ├── models.py
│           │   └── oauth2.py
│           ├── transport/           # v3.0.0 transport layer
│           │   ├── base.py
│           │   ├── http_transport.py
│           │   ├── sse_transport.py
│           │   └── stdio_transport.py
│           ├── tools/               # MCP tools
│           │   ├── factory.py
│           │   ├── base.py
│           │   ├── alerts.py
│           │   ├── agents.py
│           │   ├── cluster.py
│           │   ├── statistics.py
│           │   └── vulnerabilities.py
│           ├── analyzers/           # AI analyzers
│           │   ├── compliance_analyzer.py
│           │   └── security_analyzer.py
│           ├── prompt_enhancement/  # v2.0.0 enhancements
│           │   ├── adapters.py
│           │   ├── cache.py
│           │   ├── context_aggregator.py
│           │   ├── pipelines.py
│           │   └── updates.py
│           ├── utils/               # Utilities
│           │   ├── error_recovery.py
│           │   ├── error_standardization.py
│           │   ├── exceptions.py
│           │   ├── logging.py
│           │   ├── platform_utils.py
│           │   ├── production_error_handler.py
│           │   ├── pydantic_compat.py
│           │   ├── rate_limiter.py
│           │   ├── security_audit.py
│           │   ├── ssl_config.py
│           │   └── validation.py
│           └── scripts/             # Internal scripts
│               ├── connection_validator.py
│               └── test_connection.py
│
├── 🏗️ Production Configuration
│   └── config/
│       ├── alertmanager/
│       │   └── alertmanager.yml     # Alert routing configuration
│       ├── grafana/
│       │   └── provisioning/
│       │       └── alerting/
│       │           └── rules.yml    # Grafana alerting rules
│       ├── prometheus/
│       │   └── alerts.yml          # Prometheus alerts
│       ├── haproxy.cfg             # Load balancer configuration
│       ├── sentinel.conf           # Redis Sentinel configuration
│       └── backup.conf             # Backup configuration
│
├── 🧪 Testing
│   └── tests/
│       ├── conftest.py             # Test configuration
│       ├── fixtures/
│       │   └── mock_data.py        # Test data
│       ├── unit/                   # Unit tests
│       ├── integration/            # Integration tests
│       ├── v3/                     # v3.0.0 specific tests
│       ├── phase5/                 # Phase 5 enhancement tests
│       └── test_*.py              # Individual test files
│
├── 📝 Examples
│   └── examples/
│       ├── basic_usage.py          # Basic usage examples
│       └── configuration_examples/
│           ├── basic_config.env
│           ├── development_config.env
│           └── production_config.env
│
└── 🚫 Excluded Files (.gitignore)
    ├── venv/                       # Virtual environments
    ├── __pycache__/               # Python cache
    ├── *.log                      # Log files
    ├── .env                       # Environment files
    ├── data/                      # Runtime data
    ├── certs/                     # SSL certificates
    ├── secrets/                   # Sensitive files
    └── *.tmp                      # Temporary files
```

## 🎯 Key Features by Version

### v1.0.0 (Legacy)
- ✅ 14 core security tools
- ✅ Basic stdio transport
- ✅ macOS/Linux/Windows support

### v2.0.0 (Previous)
- ✅ All v1.0.0 features
- ✅ 26 total tools (12 new)
- ✅ Phase 5 enhancement system
- ✅ Factory architecture
- ✅ Intelligent caching

### v3.0.0 (Current)
- ✅ All v2.0.0 features
- ✅ Remote MCP server (HTTP/SSE)
- ✅ OAuth2 authentication
- ✅ Docker production deployment
- ✅ High availability configuration
- ✅ Comprehensive monitoring
- ✅ Security hardening
- ✅ Incident response procedures

## 🔄 Backward Compatibility

- **v1.0.0 → v3.0.0**: Fully compatible, no breaking changes
- **v2.0.0 → v3.0.0**: Fully compatible, no breaking changes
- **stdio mode**: Continues to work unchanged
- **Configuration**: Existing `.env` files compatible

## 🚀 Deployment Options

### Development
```bash
# Local development
python3 -m wazuh_mcp_server.main --stdio

# With Claude Desktop
# Use stdio configuration
```

### Production
```bash
# Basic production
python3 -m wazuh_mcp_server.remote_server --transport sse

# Docker production
docker compose up -d

# High availability
docker compose -f docker-compose.ha.yml up -d
```

## 📊 Repository Statistics

- **Total Files**: ~150 source files
- **Documentation**: 15+ comprehensive guides
- **Tests**: 40+ test files with 90%+ coverage
- **Scripts**: 15+ automation scripts
- **Docker**: Production-ready containerization
- **Security**: Enterprise-grade security features

## 🔐 Security Features

- OAuth2 authentication with JWT tokens
- Rate limiting and IP blocking
- SSL/TLS encryption
- Security audit logging
- Vulnerability scanning
- Compliance framework support

## 📈 Monitoring & Observability

- Prometheus metrics collection
- Grafana dashboards
- AlertManager notifications
- Health check endpoints
- Structured logging
- Performance monitoring

## 🛠️ Development Tools

- Comprehensive test suite
- Code quality tools (ruff, mypy, black)
- Security scanning (bandit, safety)
- Docker development environment
- Automated CI/CD pipelines
- Migration utilities

## 📚 Documentation Quality

- ✅ User guides for all platforms
- ✅ Production deployment guides
- ✅ Security configuration guides
- ✅ Troubleshooting documentation
- ✅ Migration guides for all versions
- ✅ API documentation
- ✅ Architecture documentation

This repository structure provides a solid foundation for production deployment, development, and maintenance of Wazuh MCP Server v3.0.0 while maintaining full backward compatibility with previous versions.