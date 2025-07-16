# Architecture Comparison: v2.0.0 vs v3.0.0

This document provides a detailed comparison between the two major versions of Wazuh MCP Server to help you choose the right version for your needs.

## Overview

| Aspect | v2.0.0 (Current) | v3.0.0 (Coming Soon) |
|--------|------------------|----------------------|
| **Status** | ✅ Production Ready | 🔜 Coming Soon |
| **Branch** | `main` | `v3-check` |
| **Transport** | stdio (local only) | HTTP/HTTPS + SSE (remote) |
| **Deployment** | Python installation | Docker containers |

---

## Transport Architecture

### v2.0.0: stdio Transport (Local)
```
┌─────────────────┐    stdio    ┌─────────────────┐
│                 │◄────────────┤                 │
│  Claude Desktop │             │  Wazuh MCP      │
│                 ├────────────►│  Server         │
└─────────────────┘             └─────────────────┘
```

**Characteristics**:
- Direct process communication
- Local execution only
- No network configuration required
- Minimal latency
- Single user access

### v3.0.0: HTTP/SSE Transport (Remote)
```
┌─────────────────┐   HTTPS/SSE   ┌─────────────────┐   API   ┌─────────────────┐
│                 │◄──────────────┤                 │◄────────┤                 │
│  Claude Desktop │               │  Wazuh MCP      │         │  Wazuh SIEM     │
│     (Client)    ├──────────────►│  Server         ├────────►│                 │
└─────────────────┘               │  (Container)    │         └─────────────────┘
                                  └─────────────────┘
```

**Characteristics**:
- Network-based communication
- Remote access capability
- Multi-user support
- OAuth2 authentication
- Scalable architecture

---

## Deployment Models

### v2.0.0: Traditional Installation

**Installation Process**:
```bash
# 1. Install dependencies on host
python3 scripts/install.py

# 2. Configure environment
cp .env.example .env

# 3. Integrate with Client
# Add to claude_desktop_config.json
```

**Requirements**:
- Python 3.9+ on host
- Manual dependency management
- Platform-specific setup
- Direct file system access

**Pros**:
- Simple installation
- Familiar Python environment
- Low resource usage
- Fast startup time

**Cons**:
- Host dependency management
- Platform-specific issues
- Single instance limitation
- Manual monitoring setup

### v3.0.0: Docker Containerization

**Deployment Process**:
```bash
# 1. Single command deployment
docker compose up -d

# 2. Automatic service orchestration
# - MCP Server
# - Redis
# - Prometheus
# - Grafana
```

**Requirements**:
- Docker 20.10+
- Docker Compose 2.0+
- 2GB RAM minimum
- Network access for remote clients

**Pros**:
- OS-independent deployment
- Complete containerization
- Built-in monitoring stack
- Horizontal scaling capability
- Production-ready from day one

**Cons**:
- Docker dependency
- Higher resource usage
- Network configuration needed
- Container management overhead

---

## Security Architecture

### v2.0.0: Basic Security

**Security Features**:
- SSL/TLS for Wazuh API connections
- Environment variable configuration
- Basic input validation
- Local process isolation

**Security Model**:
```
Host Machine
├── Python Environment
├── Environment Variables
├── Local File System
└── Network Access (Wazuh API only)
```

**Limitations**:
- No authentication layer
- Configuration stored in plain text
- Single point of failure
- No audit logging

### v3.0.0: Enterprise Security

**Security Features**:
- OAuth2 authentication and authorization
- Configuration encryption at rest
- JWT token management
- Persistent session storage
- Container security hardening
- Network segmentation
- Audit logging
- Security monitoring

**Security Model**:
```
Security Layers
├── OAuth2 Authentication
├── JWT Authorization
├── Configuration Encryption
├── Container Isolation
├── Network Security
├── Audit Logging
└── Monitoring & Alerting
```

**Benefits**:
- Multi-user authentication
- Encrypted sensitive data
- Comprehensive audit trail
- Security monitoring
- Incident response capabilities

---

## Scalability & Performance

### v2.0.0: Single Instance

**Characteristics**:
- Single Python process
- Local memory usage
- Direct stdio communication
- Host resource constraints

**Performance**:
- Startup: < 5 seconds
- Memory: < 512MB
- Response time: < 200ms (p95)
- Concurrent users: 1

**Scaling Limitations**:
- Cannot scale horizontally
- Single point of failure
- Host resource bound
- No load balancing

### v3.0.0: Horizontal Scaling

**Characteristics**:
- Container orchestration
- Load balancing with HAProxy
- Redis-based state management
- Distributed architecture

**Performance**:
- Startup: < 10 seconds (full stack)
- Memory: < 1GB (full stack)
- Response time: < 200ms (p95)
- Concurrent users: Multiple

**Scaling Capabilities**:
- Horizontal pod scaling
- Load balancing
- High availability
- Disaster recovery

---

## Monitoring & Observability

### v2.0.0: Basic Logging

**Monitoring Features**:
- Python logging
- Environment variable DEBUG mode
- Manual log analysis
- Basic error reporting

**Observability**:
```
Logs
├── Application logs
├── Error traces
└── Basic metrics
```

### v3.0.0: Full Observability Stack

**Monitoring Features**:
- Prometheus metrics collection
- Grafana dashboards
- AlertManager notifications
- Structured logging
- OpenTelemetry instrumentation
- Health checks
- Performance monitoring

**Observability Stack**:
```
Monitoring Stack
├── Prometheus (Metrics)
├── Grafana (Dashboards)
├── AlertManager (Notifications)
├── Structured Logging
├── Health Checks
├── Performance Metrics
└── Security Metrics
```

---

## Use Case Recommendations

### Choose v2.0.0 When:

✅ **Immediate Deployment Needed**
- Quick setup required
- Local development environment
- Single user access sufficient
- Minimal infrastructure overhead

✅ **Resource Constraints**
- Limited system resources
- No Docker environment
- Simple deployment preferred

✅ **Development & Testing**
- Local development workflow
- Testing and evaluation
- Learning and experimentation

### Choose v3.0.0 When:

✅ **Enterprise Requirements**
- Multi-user access needed
- Remote access required
- Production deployment
- Security compliance needed

✅ **Scalability Needs**
- High availability required
- Load balancing needed
- Disaster recovery planning
- Growth expectations

✅ **Operations Focus**
- Monitoring and alerting required
- Incident response capabilities
- Automated deployment preferred
- DevOps/container workflow

---

## Migration Path

### From v2.0.0 to v3.0.0

**Migration Steps**:
1. **Assessment**: Evaluate current v2 deployment
2. **Planning**: Design v3 architecture
3. **Testing**: Deploy v3 in test environment
4. **Configuration**: Migrate environment variables
5. **Cutover**: Switch to v3 production deployment

**Configuration Migration**:
```bash
# v2.0.0 configuration can be reused
cp .env .env.backup
git checkout v3-check
cp .env.backup .env
docker compose up -d
```

**Timeline**: 
- Small deployments: 1-2 hours
- Enterprise deployments: 1-2 days (including testing)

---

## Future Roadmap

### v2.0.0 Maintenance
- Bug fixes and security updates
- Compatibility improvements
- Long-term support (LTS)

### v3.0.0 Development
- Advanced security features
- Enhanced monitoring capabilities
- Cloud-native integrations
- Performance optimizations

---

*This comparison is current as of July 16, 2025. For the latest information, check the branch-specific documentation.*