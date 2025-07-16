# Docker Component Versions - v3.0.0

## Latest Docker Compose Specification
- **Format**: Latest Compose Specification (no version field required)
- **Compatible with**: Docker Compose CLI 1.27.0+ (Compose v2)
- **Best Practice**: Removed legacy `version: '3.8'` field

## Base Images (Latest Stable Versions)

### Application Stack
- **Python**: `3.12-slim-bookworm` (Debian 12)
  - Latest stable Python with security updates
  - Minimal Debian 12 base for security
  - Multi-architecture support (amd64, arm64)

### Monitoring & Infrastructure
- **Redis**: `7.4-alpine` 
  - Latest stable Redis with Alpine Linux base
  - Minimal attack surface with Alpine
  
- **Prometheus**: `v2.55.0`
  - Latest stable monitoring and alerting toolkit
  - Production-ready metrics collection
  
- **Grafana**: `11.4.0`
  - Latest stable visualization platform
  - Modern React-based panels
  
- **HAProxy**: `3.0-alpine`
  - Latest stable load balancer
  - Alpine Linux base for security
  
- **AlertManager**: `v0.27.0` (HA setup)
  - Latest stable alert routing and grouping

## Docker Compose Files Updated

### Basic Setup (`docker-compose.yml`)
```yaml
# Uses latest Compose Specification (no version field required)
services:
  wazuh-mcp-server:
    image: wazuh-mcp-server:3.0.0
  redis:
    image: redis:7.4-alpine
  prometheus:
    image: prom/prometheus:v2.55.0
  grafana:
    image: grafana/grafana:11.4.0
```

### High Availability (`docker-compose.ha.yml`)
```yaml
# Uses latest Compose Specification (no version field required)
services:
  load-balancer:
    image: haproxy:3.0-alpine
  prometheus-ha:
    image: prom/prometheus:v2.55.0
  grafana-ha:
    image: grafana/grafana:11.4.0
  alertmanager-ha:
    image: prom/alertmanager:v0.27.0
```

## Key Improvements

### Docker Compose Specification
- ✅ **Removed legacy version field** - Uses modern Compose Specification
- ✅ **Better validation** - Improved linting and error detection
- ✅ **Enhanced features** - Access to latest Compose features
- ✅ **Future-proof** - No version lock-in

### Security Updates
- ✅ **Latest Python 3.12** - Latest security patches and performance
- ✅ **Debian 12 (bookworm)** - Latest stable Debian with security updates
- ✅ **Alpine Linux bases** - Minimal attack surface for Redis/HAProxy
- ✅ **Pinned versions** - Reproducible builds, no `latest` tags

### Performance & Features
- ✅ **Python 3.12 performance** - Significant speed improvements
- ✅ **Redis 7.4 features** - Latest Redis capabilities
- ✅ **Prometheus 2.55** - Enhanced monitoring features
- ✅ **Grafana 11.4** - Modern React-based UI
- ✅ **HAProxy 3.0** - Latest load balancing features

## Deployment Commands

### Standard Deployment
```bash
# Uses latest Compose Specification
docker compose up -d
```

### High Availability Deployment
```bash
# Uses latest Compose Specification
docker compose -f docker-compose.ha.yml up -d
```

## Version Verification
```bash
# Check Compose version (should be 2.x)
docker compose version

# Verify container versions
docker compose ps
docker compose exec wazuh-mcp-server python --version
docker compose exec redis redis-server --version
```

---

**Note**: All Docker images use specific version tags (not `latest`) for reproducible deployments while ensuring we use the most current stable versions available as of July 2025.