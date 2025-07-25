# Docker Deployment Guide

Complete guide for deploying Wazuh MCP Server using Docker in development and production environments.

## Overview

Docker deployment provides:
- **Consistent Environment**: Same runtime across all systems
- **Easy Deployment**: One-command deployment with Docker Compose
- **Scalability**: Easy horizontal scaling and load balancing
- **Security Isolation**: Container-based security boundaries
- **Health Monitoring**: Built-in health checks and monitoring

## Quick Start

### Prerequisites

```bash
# Verify Docker installation
docker --version                # Should be 20.10+
docker compose version          # Should be 2.0+

# Check system resources
docker system df               # Available disk space
docker system info            # System information
```

### Basic Deployment

```bash
# 1. Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server

# 2. Configure environment
cp docker/.env.docker.template .env
# Edit .env with your Wazuh server details

# 3. Deploy
docker compose up -d

# 4. Verify deployment
docker compose ps
docker compose logs --follow wazuh-mcp-server
```

## Configuration

### Environment Variables

**Core Configuration (.env):**
```bash
# Wazuh Server Configuration
WAZUH_HOST=your-wazuh-server.com
WAZUH_PORT=55000
WAZUH_USER=mcp-api-user
WAZUH_PASS=YourSecurePassword123!

# MCP Transport Configuration
MCP_TRANSPORT=stdio              # stdio or http
MCP_HOST=0.0.0.0                # For HTTP mode
MCP_PORT=3000                   # For HTTP mode

# Security Configuration
VERIFY_SSL=true
JWT_SECRET_KEY=your-secret-key

# Performance Configuration
MAX_CONNECTIONS=10
REQUEST_TIMEOUT_SECONDS=30
LOG_LEVEL=INFO
```

**Production Environment (.env.production):**
```bash
# Production settings
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=INFO

# Enhanced security
VERIFY_SSL=true
ENABLE_RATE_LIMITING=true
ENABLE_AUDIT_LOGGING=true
JWT_SECRET_KEY=$(openssl rand -base64 32)

# Performance optimization
MAX_CONNECTIONS=20
POOL_SIZE=10
CACHE_TTL_SECONDS=300
```

### Docker Compose Configurations

#### Development (docker-compose.yml)

```yaml
version: '3.8'

services:
  wazuh-mcp-server:
    build: .
    container_name: wazuh-mcp-server
    restart: unless-stopped
    environment:
      - MCP_TRANSPORT=${MCP_TRANSPORT:-stdio}
      - WAZUH_HOST=${WAZUH_HOST}
      - WAZUH_USER=${WAZUH_USER}
      - WAZUH_PASS=${WAZUH_PASS}
      - LOG_LEVEL=${LOG_LEVEL:-INFO}
    ports:
      - "${MCP_PORT:-3000}:3000"
    volumes:
      - ./logs:/app/logs
      - ./.env:/app/.env:ro
    healthcheck:
      test: ["CMD", "python3", "-c", "import sys; sys.path.insert(0, '/app/src'); from wazuh_mcp_server.config import WazuhConfig; WazuhConfig.from_env()"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
    networks:
      - wazuh-mcp-network

networks:
  wazuh-mcp-network:
    driver: bridge
```

#### Production (docker-compose.prod.yml)

```yaml
version: '3.8'

services:
  wazuh-mcp-server:
    build:
      context: .
      target: production
    image: wazuh-mcp-server:production
    container_name: wazuh-mcp-server-prod
    restart: unless-stopped
    
    # Security configuration
    user: "1000:1000"
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    
    environment:
      - ENVIRONMENT=production
      - MCP_TRANSPORT=${MCP_TRANSPORT:-http}
      - WAZUH_HOST=${WAZUH_HOST}
      - WAZUH_USER=${WAZUH_USER}
      - WAZUH_PASS=${WAZUH_PASS}
      - JWT_SECRET_KEY=${JWT_SECRET_KEY}
      - VERIFY_SSL=true
      - ENABLE_RATE_LIMITING=true
      - LOG_LEVEL=INFO
      
    ports:
      - "3000:3000"
      
    volumes:
      - ./logs:/app/logs
      - /tmp:/tmp
      - type: tmpfs
        target: /app/tmp
        tmpfs:
          size: 100M
          
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
      
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s
      
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
          
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        
    networks:
      - wazuh-mcp-network

  # Optional: Reverse proxy for production
  nginx:
    image: nginx:alpine
    container_name: wazuh-mcp-nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/ssl:/etc/nginx/ssl:ro
    depends_on:
      - wazuh-mcp-server
    networks:
      - wazuh-mcp-network

networks:
  wazuh-mcp-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
```

#### High Availability (docker-compose.ha.yml)

```yaml
version: '3.8'

services:
  wazuh-mcp-server:
    build: .
    image: wazuh-mcp-server:latest
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      update_config:
        parallelism: 1
        delay: 10s
        failure_action: rollback
      resources:
        limits:
          cpus: '0.5'
          memory: 512M
        reservations:
          cpus: '0.25'
          memory: 256M
    environment:
      - MCP_TRANSPORT=http
      - WAZUH_HOST=${WAZUH_HOST}
      - WAZUH_USER=${WAZUH_USER}
      - WAZUH_PASS=${WAZUH_PASS}
    networks:
      - wazuh-mcp-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  load-balancer:
    image: haproxy:alpine
    ports:
      - "3000:3000"
      - "8080:8080"  # HAProxy stats
    volumes:
      - ./haproxy/haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    depends_on:
      - wazuh-mcp-server
    networks:
      - wazuh-mcp-network

networks:
  wazuh-mcp-network:
    driver: overlay
    attachable: true
```

## Deployment Modes

### STDIO Mode (Claude Desktop)

For local Claude Desktop integration:

```bash
# 1. Start container in STDIO mode
export MCP_TRANSPORT=stdio
docker compose up -d

# 2. Configure Claude Desktop
# ~/.config/claude/claude_desktop_config.json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": [
        "exec", "-i", "wazuh-mcp-server", 
        "./wazuh-mcp-server", "--stdio"
      ]
    }
  }
}

# 3. Restart Claude Desktop
```

**Verification:**
```bash
# Test STDIO communication
echo '{"method": "initialize", "params": {}}' | \
docker exec -i wazuh-mcp-server ./wazuh-mcp-server --stdio
```

### HTTP Mode (Remote Access)

For remote access and API integration:

```bash
# 1. Start container in HTTP mode
export MCP_TRANSPORT=http
export MCP_HOST=0.0.0.0
export MCP_PORT=3000
docker compose up -d

# 2. Test HTTP endpoints
curl http://localhost:3000/health
curl http://localhost:3000/capabilities

# 3. Access MCP over HTTP/SSE
curl -X POST http://localhost:3000/rpc \
  -H "Content-Type: application/json" \
  -d '{"method": "tools/list", "params": {}}'
```

## Monitoring & Health Checks

### Built-in Health Checks

**Container Health Check:**
```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD python3 -c "import sys; sys.path.insert(0, '/app/src'); from wazuh_mcp_server.config import WazuhConfig; WazuhConfig.from_env()" || exit 1
```

**Application Health Endpoints:**
```bash
# Basic health check
curl http://localhost:3000/health

# Detailed system status
curl http://localhost:3000/status

# Performance metrics
curl http://localhost:3000/metrics
```

### Docker Monitoring

**Container Stats:**
```bash
# Real-time container stats
docker stats wazuh-mcp-server

# Container resource usage
docker exec wazuh-mcp-server top

# Memory usage
docker exec wazuh-mcp-server free -h

# Disk usage
docker exec wazuh-mcp-server df -h
```

**Log Monitoring:**
```bash
# Container logs
docker compose logs --follow wazuh-mcp-server

# Application logs
docker exec wazuh-mcp-server tail -f logs/app.log

# Error logs only
docker compose logs wazuh-mcp-server | grep ERROR

# Structured log parsing
docker compose logs --no-log-prefix wazuh-mcp-server | jq '.'
```

### Performance Monitoring

**Prometheus Integration:**
```yaml
# docker-compose.monitoring.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

  grafana:
    image: grafana/grafana
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-storage:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards

volumes:
  grafana-storage:
```

## Security Configuration

### Container Security

**Security Hardening:**
```yaml
services:
  wazuh-mcp-server:
    # Run as non-root user
    user: "1000:1000"
    
    # Read-only filesystem
    read_only: true
    
    # Security options
    security_opt:
      - no-new-privileges:true
      - seccomp:unconfined
      
    # Drop all capabilities
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
      
    # Temporary filesystems
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
      - /var/run:noexec,nosuid,size=50m
```

**Network Security:**
```yaml
networks:
  wazuh-mcp-network:
    driver: bridge
    ipam:
      driver: default
      config:
        - subnet: 172.20.0.0/24
          gateway: 172.20.0.1
    driver_opts:
      com.docker.network.bridge.enable_icc: "false"
      com.docker.network.bridge.enable_ip_masquerade: "true"
```

### Secrets Management

**Docker Secrets:**
```yaml
version: '3.8'

services:
  wazuh-mcp-server:
    image: wazuh-mcp-server:latest
    secrets:
      - wazuh_password
      - jwt_secret
    environment:
      - WAZUH_PASS_FILE=/run/secrets/wazuh_password
      - JWT_SECRET_FILE=/run/secrets/jwt_secret

secrets:
  wazuh_password:
    file: ./secrets/wazuh_password.txt
  jwt_secret:
    file: ./secrets/jwt_secret.txt
```

**External Secrets (Kubernetes):**
```yaml
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: wazuh-mcp-secrets
spec:
  provider:
    vault:
      server: "https://vault.company.com"
      path: "secret"
      version: "v2"
```

## Scaling & Load Balancing

### Horizontal Scaling

**Docker Swarm:**
```bash
# Initialize swarm
docker swarm init

# Deploy stack
docker stack deploy -c docker-compose.ha.yml wazuh-mcp

# Scale service
docker service scale wazuh-mcp_wazuh-mcp-server=5

# Check service status
docker service ls
docker service ps wazuh-mcp_wazuh-mcp-server
```

**Load Balancer Configuration (HAProxy):**
```
global
    daemon

defaults
    mode http
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms

frontend wazuh_mcp_frontend
    bind *:3000
    default_backend wazuh_mcp_backend

backend wazuh_mcp_backend
    balance roundrobin
    option httpchk GET /health
    server server1 wazuh-mcp-server_1:3000 check
    server server2 wazuh-mcp-server_2:3000 check
    server server3 wazuh-mcp-server_3:3000 check
```

### Kubernetes Deployment

**Deployment Manifest:**
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wazuh-mcp-server
  labels:
    app: wazuh-mcp-server
spec:
  replicas: 3
  selector:
    matchLabels:
      app: wazuh-mcp-server
  template:
    metadata:
      labels:
        app: wazuh-mcp-server
    spec:
      containers:
      - name: wazuh-mcp-server
        image: wazuh-mcp-server:latest
        ports:
        - containerPort: 3000
        env:
        - name: MCP_TRANSPORT
          value: "http"
        - name: WAZUH_HOST
          valueFrom:
            secretKeyRef:
              name: wazuh-credentials
              key: host
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
          requests:
            memory: "256Mi"
            cpu: "250m"
---
apiVersion: v1
kind: Service
metadata:
  name: wazuh-mcp-service
spec:
  selector:
    app: wazuh-mcp-server
  ports:
    - protocol: TCP
      port: 80
      targetPort: 3000
  type: LoadBalancer
```

## Troubleshooting

### Common Issues

**Container Won't Start:**
```bash
# Check container logs
docker compose logs wazuh-mcp-server

# Check configuration
docker exec wazuh-mcp-server python3 validate-production.py

# Test connectivity
docker exec wazuh-mcp-server curl -k https://$WAZUH_HOST:55000/
```

**Performance Issues:**
```bash
# Monitor resource usage
docker stats wazuh-mcp-server

# Check system limits
docker exec wazuh-mcp-server ulimit -a

# Memory analysis
docker exec wazuh-mcp-server free -h
docker exec wazuh-mcp-server ps aux --sort=-%mem
```

**Network Connectivity:**
```bash
# Test container networking
docker exec wazuh-mcp-server ping $WAZUH_HOST

# Check port accessibility
docker exec wazuh-mcp-server nc -zv $WAZUH_HOST 55000

# Network debugging
docker network ls
docker network inspect wazuh-mcp-server_default
```

### Debug Mode

**Enable Debug Logging:**
```bash
# Set debug environment
export LOG_LEVEL=DEBUG
export ENABLE_DEBUG_LOGGING=true

# Restart with debug
docker compose down
docker compose up -d

# Monitor debug logs
docker compose logs --follow wazuh-mcp-server | grep DEBUG
```

**Interactive Debugging:**
```bash
# Access container shell
docker exec -it wazuh-mcp-server bash

# Run components manually
python3 validate-production.py --verbose
python3 -c "from src.wazuh_mcp_server.server import main; main()"

# Test individual components
python3 -c "
from src.wazuh_mcp_server.config import WazuhConfig
config = WazuhConfig.from_env()
print('Config valid!')
"
```

## Backup & Recovery

### Data Backup

**Configuration Backup:**
```bash
# Backup configuration
tar -czf wazuh-mcp-backup-$(date +%Y%m%d).tar.gz \
  .env docker-compose.yml logs/ config/

# Automated backup script
#!/bin/bash
BACKUP_DIR="/backups/wazuh-mcp"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR
tar -czf $BACKUP_DIR/wazuh-mcp-$DATE.tar.gz \
  .env docker-compose.yml logs/ config/

# Keep only last 7 days
find $BACKUP_DIR -name "wazuh-mcp-*.tar.gz" -mtime +7 -delete
```

**Container Backup:**
```bash
# Export container state
docker commit wazuh-mcp-server wazuh-mcp-server:backup-$(date +%Y%m%d)

# Save image
docker save wazuh-mcp-server:backup-$(date +%Y%m%d) | \
  gzip > wazuh-mcp-backup-$(date +%Y%m%d).tar.gz
```

### Disaster Recovery

**Recovery Procedure:**
```bash
# 1. Restore configuration
tar -xzf wazuh-mcp-backup-20240101.tar.gz

# 2. Rebuild container
docker compose build --no-cache

# 3. Start services
docker compose up -d

# 4. Verify functionality
docker compose exec wazuh-mcp-server python3 validate-production.py

# 5. Test endpoints
curl http://localhost:3000/health
```

**High Availability Setup:**
```bash
# Multi-region deployment
docker stack deploy -c docker-compose.ha.yml wazuh-mcp

# Database replication (if using external DB)
# Application-level clustering
# Load balancer health checks
```

## Performance Optimization

### Container Optimization

**Multi-stage Build:**
```dockerfile
# Build stage
FROM python:3.11-slim as builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --user -r requirements.txt

# Production stage
FROM python:3.11-slim
COPY --from=builder /root/.local /home/wazuh/.local
COPY src/ ./src/
USER wazuh
```

**Resource Limits:**
```yaml
services:
  wazuh-mcp-server:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
```

### Performance Tuning

**Environment Variables:**
```bash
# Performance optimization
MAX_CONNECTIONS=20
POOL_SIZE=10
CACHE_TTL_SECONDS=300
REQUEST_TIMEOUT_SECONDS=30

# Memory management
PYTHON_GC_THRESHOLD=700,10,10
MALLOC_TRIM_THRESHOLD=65536
```

**Volume Optimization:**
```yaml
volumes:
  # Use tmpfs for temporary data
  - type: tmpfs
    target: /app/tmp
    tmpfs:
      size: 100M
      
  # Bind mount for logs (better performance)
  - ./logs:/app/logs:Z
```

For additional Docker resources:
- [Docker Security Best Practices](docker-security.md)
- [Kubernetes Deployment Guide](kubernetes-guide.md)  
- [Performance Tuning](performance-tuning.md)
- [Monitoring Setup](monitoring-setup.md)