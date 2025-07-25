# Wazuh Administrator's Guide to MCP Server

A comprehensive guide for Wazuh administrators to deploy, configure, and maintain the Wazuh MCP Server in production environments.

## 📋 Table of Contents

- [Overview for Wazuh Administrators](#overview-for-wazuh-administrators)
- [Prerequisites and Planning](#prerequisites-and-planning)
- [Wazuh Infrastructure Integration](#wazuh-infrastructure-integration)
- [Production Deployment Strategies](#production-deployment-strategies)
- [Configuration Management](#configuration-management)
- [Security Hardening](#security-hardening)
- [Monitoring and Maintenance](#monitoring-and-maintenance)
- [Performance Optimization](#performance-optimization)
- [Troubleshooting Guide](#troubleshooting-guide)
- [Backup and Disaster Recovery](#backup-and-disaster-recovery)
- [Compliance and Auditing](#compliance-and-auditing)

---

## 🎯 Overview for Wazuh Administrators

### What is Wazuh MCP Server?

The Wazuh MCP Server is a production-ready bridge that connects your Wazuh SIEM infrastructure with AI assistants like Claude, enabling intelligent security operations through natural language interfaces.

### Architecture Overview

```
┌─────────────────────────────────────────┐
│            AI Assistant Layer           │
│  ├─ Claude Desktop                     │
│  ├─ Custom MCP Clients                 │
│  └─ API Integrations                   │
└─────────────────────────────────────────┘
               │ MCP Protocol
┌─────────────────────────────────────────┐
│          Wazuh MCP Server               │
│  ├─ Authentication & Authorization     │
│  ├─ Rate Limiting & Security           │
│  ├─ API Abstraction Layer              │
│  └─ Connection Management              │
└─────────────────────────────────────────┘
               │ REST API / Elasticsearch API
┌─────────────────────────────────────────┐
│         Your Wazuh Infrastructure       │
│  ├─ Wazuh Manager (API Server)         │
│  ├─ Wazuh Indexer (Data Storage)       │
│  ├─ Wazuh Dashboard (Web UI)           │
│  └─ Wazuh Agents (Data Collectors)     │
└─────────────────────────────────────────┘
```

### Key Benefits for Wazuh Administrators

- **Enhanced Analysis**: AI-powered threat analysis and correlation
- **Faster Response**: Natural language queries for rapid investigation
- **Automation**: Streamlined security operations workflows
- **Scalability**: Handles high-volume environments efficiently
- **Integration**: Seamless integration with existing Wazuh deployments
- **Security**: Enterprise-grade security and access controls

### Supported Wazuh Versions

- **Wazuh Manager**: 4.0+ (4.8+ recommended)
- **Wazuh Indexer**: 4.8+ (for enhanced features)
- **API Version**: v4 (primary), v3 (legacy support)

---

## 🔧 Prerequisites and Planning

### Infrastructure Requirements

#### Minimum System Requirements
- **CPU**: 2 vCPUs
- **RAM**: 4GB
- **Storage**: 20GB SSD
- **Network**: 1Gbps connection to Wazuh infrastructure

#### Recommended Production Requirements
- **CPU**: 4-8 vCPUs
- **RAM**: 8-16GB
- **Storage**: 50GB SSD (with log retention)
- **Network**: 10Gbps connection, redundant paths
- **Load Balancer**: For high availability deployments

#### Network Requirements

**Outbound Connections (MCP Server → Wazuh):**
- Wazuh Manager: Port 55000 (HTTPS)
- Wazuh Indexer: Port 9200 (HTTPS) - Optional but recommended

**Inbound Connections (Clients → MCP Server):**
- HTTP Mode: Port 3000 (HTTPS recommended)
- STDIO Mode: No inbound connections required

**Security Considerations:**
- TLS 1.2+ required for all connections
- Certificate validation enabled
- Network segmentation recommended

### Wazuh Infrastructure Assessment

#### Pre-deployment Checklist

```bash
# 1. Verify Wazuh Manager API access
curl -k -X GET "https://your-wazuh-manager:55000/" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# 2. Check API user permissions
curl -k -X GET "https://your-wazuh-manager:55000/security/users/me" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# 3. Test Indexer connectivity (if using separate indexer)
curl -k -X GET "https://your-wazuh-indexer:9200/_cluster/health" \
  -u "username:password"

# 4. Verify SSL certificate configuration
openssl s_client -connect your-wazuh-manager:55000 -servername your-wazuh-manager

# 5. Check current API rate limits
curl -k -X GET "https://your-wazuh-manager:55000/manager/info" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### Capacity Planning

**API Rate Limiting Considerations:**
- Default Wazuh API: 300 requests/minute
- MCP Server default: 100 requests/minute
- Adjust based on expected usage patterns

**Data Volume Estimates:**
- Alert queries: ~1MB per 1000 alerts
- Agent data: ~100KB per 100 agents
- Statistics: ~50KB per request
- Cache storage: 10-100MB depending on configuration

---

## 🏗️ Wazuh Infrastructure Integration

### API User Configuration

#### Creating Dedicated MCP API User

**Step 1: Create API User**
```bash
# Create user with strong password
curl -k -X POST "https://your-wazuh-manager:55000/security/users" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "mcp-server",
    "password": "ComplexMCPPassword2024!@#"
  }'
```

**Step 2: Create Custom Role with Minimal Permissions**
```bash
# Create read-only role for MCP operations
curl -k -X POST "https://your-wazuh-manager:55000/security/roles" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "mcp-readonly",
    "policies": [
      "agents:read",
      "alerts:read",
      "rules:read",
      "decoders:read",
      "manager:read",
      "cluster:read",
      "ciscat:read",
      "syscollector:read",
      "vulnerability:read",
      "active-response:read"
    ],
    "rules": [
      {
        "resource": "*:*:*",
        "effect": "allow",
        "actions": ["read"]
      }
    ]
  }'
```

**Step 3: Assign Role to User**
```bash
curl -k -X POST "https://your-wazuh-manager:55000/security/users/mcp-server/roles" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role_ids": ["mcp-readonly"]}'
```

**Step 4: Verify User Configuration**
```bash
# Test user authentication
curl -k -X POST "https://your-wazuh-manager:55000/security/user/authenticate" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "mcp-server",
    "password": "ComplexMCPPassword2024!@#"
  }'

# Verify permissions
curl -k -X GET "https://your-wazuh-manager:55000/security/users/mcp-server" \
  -H "Authorization: Bearer $NEW_JWT_TOKEN"
```

### Distributed Wazuh Setup Integration

#### Single Manager Configuration
```bash
# Basic single-manager setup
WAZUH_HOST=wazuh-manager.company.com
WAZUH_PORT=55000
WAZUH_USER=mcp-server
WAZUH_PASS=ComplexMCPPassword2024!@#

# Optional indexer (if co-located)
USE_INDEXER_FOR_ALERTS=true
USE_INDEXER_FOR_VULNERABILITIES=true
```

#### Distributed Architecture Configuration
```bash
# Wazuh Manager (API and management)
WAZUH_HOST=wazuh-manager.company.com
WAZUH_PORT=55000
WAZUH_USER=mcp-server
WAZUH_PASS=ComplexMCPPassword2024!@#

# Wazuh Indexer (separate data storage)
WAZUH_INDEXER_HOST=wazuh-indexer.company.com
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=mcp-indexer-user
WAZUH_INDEXER_PASS=ComplexIndexerPassword2024!@#

# Feature flags
USE_INDEXER_FOR_ALERTS=true
USE_INDEXER_FOR_VULNERABILITIES=true
USE_INDEXER_FOR_STATISTICS=true
PREFER_INDEXER_FOR_LARGE_QUERIES=true
```

#### Multi-Cluster Setup
```bash
# Primary cluster
WAZUH_HOST=wazuh-primary.company.com
WAZUH_INDEXER_HOST=indexer-primary.company.com

# Failover configuration
WAZUH_BACKUP_HOST=wazuh-secondary.company.com
WAZUH_INDEXER_BACKUP_HOST=indexer-secondary.company.com

# Load balancing
ENABLE_CLUSTER_FAILOVER=true
CLUSTER_HEALTH_CHECK_INTERVAL=30
```

### SSL/TLS Certificate Management

#### Certificate Requirements

**Production Certificate Checklist:**
- [ ] Valid SSL certificate from trusted CA
- [ ] Certificate includes all hostnames/IPs
- [ ] Certificate chain is complete
- [ ] Private key is properly secured
- [ ] Certificate expiration monitoring enabled

#### Custom CA Configuration

```bash
# Custom CA certificate bundle
CA_BUNDLE_PATH=/etc/ssl/certs/company-ca.pem
WAZUH_CA_BUNDLE_PATH=/etc/ssl/certs/wazuh-ca.pem

# Client certificate authentication (if required)
CLIENT_CERT_PATH=/etc/ssl/certs/mcp-client.crt
CLIENT_KEY_PATH=/etc/ssl/private/mcp-client.key

# Indexer SSL configuration (if different)
WAZUH_INDEXER_VERIFY_SSL=true
INDEXER_CA_BUNDLE_PATH=/etc/ssl/certs/indexer-ca.pem
```

#### Certificate Validation Script

```bash
#!/bin/bash
# validate-certificates.sh - Validate SSL certificates

set -e

WAZUH_HOST=${1:-$WAZUH_HOST}
WAZUH_PORT=${2:-55000}
INDEXER_HOST=${3:-$WAZUH_INDEXER_HOST}
INDEXER_PORT=${4:-9200}

echo "🔒 Validating Wazuh Manager certificate..."
openssl s_client -connect $WAZUH_HOST:$WAZUH_PORT -servername $WAZUH_HOST < /dev/null 2>/dev/null | \
openssl x509 -noout -dates -subject -issuer

echo "🔒 Testing Wazuh Manager SSL connection..."
curl -I -s -o /dev/null -w "%{http_code}\n" https://$WAZUH_HOST:$WAZUH_PORT/

if [ ! -z "$INDEXER_HOST" ]; then
    echo "🔒 Validating Indexer certificate..."
    openssl s_client -connect $INDEXER_HOST:$INDEXER_PORT -servername $INDEXER_HOST < /dev/null 2>/dev/null | \
    openssl x509 -noout -dates -subject -issuer
    
    echo "🔒 Testing Indexer SSL connection..."
    curl -I -s -o /dev/null -w "%{http_code}\n" https://$INDEXER_HOST:$INDEXER_PORT/
fi

echo "✅ Certificate validation completed"
```

---

## 🚀 Production Deployment Strategies

### Deployment Architecture Options

#### Option 1: Single Instance Deployment

**Best for:**
- Small to medium Wazuh deployments
- Development and testing environments
- Simple maintenance requirements

```yaml
# docker-compose.yml - Single instance
version: '3.8'
services:
  wazuh-mcp-server:
    image: wazuh-mcp-server:latest
    container_name: wazuh-mcp-prod
    restart: unless-stopped
    env_file: .env.production
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
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1.0'
        reservations:
          memory: 512M
          cpus: '0.5'
```

#### Option 2: High Availability Deployment

**Best for:**
- Large enterprise environments
- Mission-critical security operations
- 24/7 availability requirements

```yaml
# docker-compose.ha.yml - High availability
version: '3.8'
services:
  wazuh-mcp-server-1:
    image: wazuh-mcp-server:latest
    container_name: wazuh-mcp-primary
    restart: unless-stopped
    env_file: .env.production
    environment:
      - INSTANCE_ID=primary
      - CLUSTER_MODE=true
    volumes:
      - ./logs:/app/logs
      - ./config:/app/config:ro
    healthcheck:
      test: ["CMD", "python3", "validate-production.py", "--quick"]
      interval: 30s
      timeout: 10s
      retries: 3

  wazuh-mcp-server-2:
    image: wazuh-mcp-server:latest
    container_name: wazuh-mcp-secondary
    restart: unless-stopped
    env_file: .env.production
    environment:
      - INSTANCE_ID=secondary
      - CLUSTER_MODE=true
    volumes:
      - ./logs:/app/logs
      - ./config:/app/config:ro
    healthcheck:
      test: ["CMD", "python3", "validate-production.py", "--quick"]
      interval: 30s
      timeout: 10s
      retries: 3

  nginx-loadbalancer:
    image: nginx:alpine
    container_name: wazuh-mcp-lb
    restart: unless-stopped
    ports:
      - "3000:80"
      - "3443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/nginx/ssl:ro
    depends_on:
      - wazuh-mcp-server-1
      - wazuh-mcp-server-2
```

#### Option 3: Kubernetes Deployment

**Best for:**
- Container orchestration environments
- Auto-scaling requirements
- Cloud-native deployments

```yaml
# kubernetes-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: wazuh-mcp-server
  namespace: security
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
        - name: WAZUH_HOST
          valueFrom:
            secretKeyRef:
              name: wazuh-credentials
              key: host
        - name: WAZUH_USER
          valueFrom:
            secretKeyRef:
              name: wazuh-credentials
              key: username
        - name: WAZUH_PASS
          valueFrom:
            secretKeyRef:
              name: wazuh-credentials
              key: password
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          limits:
            memory: "1Gi"
            cpu: "1000m"
          requests:
            memory: "512Mi"
            cpu: "500m"
---
apiVersion: v1
kind: Service
metadata:
  name: wazuh-mcp-service
  namespace: security
spec:
  selector:
    app: wazuh-mcp-server
  ports:
  - protocol: TCP
    port: 3000
    targetPort: 3000
  type: LoadBalancer
```

### Load Balancer Configuration

#### Nginx Configuration for HA
```nginx
# nginx.conf
upstream wazuh_mcp_backend {
    least_conn;
    server wazuh-mcp-server-1:3000 max_fails=3 fail_timeout=30s;
    server wazuh-mcp-server-2:3000 max_fails=3 fail_timeout=30s backup;
}

server {
    listen 80;
    listen 443 ssl http2;
    server_name mcp.wazuh.company.com;

    # SSL configuration
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM;
    ssl_prefer_server_ciphers off;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=mcp_api:10m rate=10r/s;
    limit_req zone=mcp_api burst=20 nodelay;

    # Health check endpoint
    location /health {
        access_log off;
        proxy_pass http://wazuh_mcp_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_connect_timeout 5s;
        proxy_read_timeout 5s;
    }

    # Main API endpoints
    location / {
        proxy_pass http://wazuh_mcp_backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket support for MCP
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        
        # Timeouts
        proxy_connect_timeout 30s;
        proxy_read_timeout 300s;
        proxy_send_timeout 30s;
    }
}
```

---

## ⚙️ Configuration Management

### Environment Configuration Strategy

#### Configuration Hierarchy
1. **Default Configuration**: Built-in secure defaults
2. **Environment Files**: `.env` files for each environment
3. **Environment Variables**: Runtime overrides
4. **Configuration Files**: Advanced settings in JSON/YAML

#### Production Environment Configuration

```bash
# .env.production - Production configuration template

# === WAZUH INFRASTRUCTURE ===
# Wazuh Manager Configuration
WAZUH_HOST=wazuh-manager.company.com
WAZUH_PORT=55000
WAZUH_USER=mcp-server
WAZUH_PASS=ComplexMCPPassword2024!@#
WAZUH_API_VERSION=v4

# Wazuh Indexer Configuration (if separate)
WAZUH_INDEXER_HOST=wazuh-indexer.company.com
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=mcp-indexer-user
WAZUH_INDEXER_PASS=ComplexIndexerPassword2024!@#

# === SSL/TLS CONFIGURATION ===
VERIFY_SSL=true
WAZUH_SSL_VERIFY=true
SSL_TIMEOUT=30
ALLOW_SELF_SIGNED=false
CA_BUNDLE_PATH=/etc/ssl/certs/ca-certificates.crt

# === MCP SERVER CONFIGURATION ===
MCP_TRANSPORT=http
MCP_HOST=0.0.0.0
MCP_PORT=3000
SERVER_NAME=wazuh-mcp-server

# === SECURITY SETTINGS ===
JWT_SECRET_KEY=your-256-bit-secret-key-here
TOKEN_EXPIRY_MINUTES=30
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=15

# === PERFORMANCE TUNING ===
MAX_CONNECTIONS=50
POOL_SIZE=25
REQUEST_TIMEOUT_SECONDS=30
MAX_ALERTS_PER_QUERY=1000
CACHE_TTL_SECONDS=300

# === RATE LIMITING ===
MAX_REQUESTS_PER_MINUTE=100
BURST_REQUEST_SIZE=20
ENABLE_RATE_LIMITING=true

# === LOGGING CONFIGURATION ===
LOG_LEVEL=INFO
STRUCTURED_LOGGING=true
ENABLE_LOG_ROTATION=true
LOG_DIR=/var/log/wazuh-mcp-server
MAX_LOG_SIZE_MB=100
LOG_BACKUP_COUNT=10

# === MONITORING ===
ENABLE_METRICS=true
ENABLE_HEALTH_CHECKS=true
HEALTH_CHECK_INTERVAL=30
METRICS_PORT=9090

# === FEATURE FLAGS ===
USE_INDEXER_FOR_ALERTS=true
USE_INDEXER_FOR_VULNERABILITIES=true
ENABLE_EXTERNAL_INTEL=false
ENABLE_ML_ANALYSIS=true
ENABLE_COMPLIANCE_CHECKING=true

# === ENVIRONMENT ===
ENVIRONMENT=production
DEBUG=false
```

#### Configuration Validation

```bash
#!/bin/bash
# validate-config.sh - Validate production configuration

set -e

CONFIG_FILE=${1:-.env}

echo "🔍 Validating configuration file: $CONFIG_FILE"

# Check if file exists
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "❌ Configuration file not found: $CONFIG_FILE"
    exit 1
fi

# Source the configuration
source $CONFIG_FILE

# Required variables
REQUIRED_VARS=(
    "WAZUH_HOST"
    "WAZUH_USER"
    "WAZUH_PASS"
    "JWT_SECRET_KEY"
)

# Validate required variables
for var in "${REQUIRED_VARS[@]}"; do
    if [[ -z "${!var}" ]]; then
        echo "❌ Required variable $var is not set"
        exit 1
    fi
done

# Validate JWT secret key strength
if [[ ${#JWT_SECRET_KEY} -lt 32 ]]; then
    echo "❌ JWT_SECRET_KEY too short (minimum 32 characters)"
    exit 1
fi

# Validate password strength
if [[ ${#WAZUH_PASS} -lt 12 ]]; then
    echo "⚠️  WARNING: WAZUH_PASS is weak (less than 12 characters)"
fi

# Check production security settings
if [[ "$ENVIRONMENT" == "production" ]]; then
    if [[ "$VERIFY_SSL" != "true" ]]; then
        echo "❌ SSL verification must be enabled in production"
        exit 1
    fi
    
    if [[ "$DEBUG" == "true" ]]; then
        echo "⚠️  WARNING: Debug mode enabled in production"
    fi
    
    if [[ "$LOG_LEVEL" == "DEBUG" ]]; then
        echo "⚠️  WARNING: Debug logging enabled in production"
    fi
fi

# Validate network connectivity
echo "🌐 Testing Wazuh connectivity..."
if curl -k -s --connect-timeout 10 https://$WAZUH_HOST:$WAZUH_PORT/ > /dev/null; then
    echo "✅ Wazuh Manager is reachable"
else
    echo "❌ Cannot reach Wazuh Manager at $WAZUH_HOST:$WAZUH_PORT"
    exit 1
fi

# Test indexer connectivity if configured
if [[ ! -z "$WAZUH_INDEXER_HOST" ]]; then
    echo "🗃️  Testing Indexer connectivity..."
    if curl -k -s --connect-timeout 10 https://$WAZUH_INDEXER_HOST:$WAZUH_INDEXER_PORT/ > /dev/null; then
        echo "✅ Wazuh Indexer is reachable"
    else
        echo "❌ Cannot reach Wazuh Indexer at $WAZUH_INDEXER_HOST:$WAZUH_INDEXER_PORT"
    fi
fi

echo "✅ Configuration validation completed successfully"
```

### Advanced Configuration Options

#### Feature Flag Management
```bash
# Feature flags for gradual rollout
FEATURE_ENHANCED_ANALYTICS=true
FEATURE_REAL_TIME_ALERTS=false
FEATURE_CUSTOM_DASHBOARDS=true
FEATURE_API_V5_SUPPORT=false

# A/B testing configuration
ENABLE_AB_TESTING=true
AB_TEST_COHORTS=["control", "experiment_a", "experiment_b"]
AB_TEST_TRAFFIC_SPLIT={"control": 50, "experiment_a": 25, "experiment_b": 25}
```

#### Multi-Environment Configuration
```bash
# config/environments/production.env
# Production-specific overrides
MAX_CONNECTIONS=100
CACHE_TTL_SECONDS=600
LOG_LEVEL=INFO

# config/environments/staging.env
# Staging-specific overrides
MAX_CONNECTIONS=25
CACHE_TTL_SECONDS=60
LOG_LEVEL=DEBUG

# config/environments/development.env
# Development-specific overrides
VERIFY_SSL=false
MAX_CONNECTIONS=5
CACHE_TTL_SECONDS=10
LOG_LEVEL=DEBUG
DEBUG=true
```

---

## 🔒 Security Hardening

### Infrastructure Security

#### Network Security Configuration

```bash
# Firewall configuration (using ufw)
# Allow only necessary ports
ufw allow 3000/tcp comment "MCP HTTP API"
ufw allow from 10.0.0.0/8 to any port 22 comment "SSH from internal network"

# Block all other inbound traffic
ufw default deny incoming
ufw default allow outgoing

# Enable firewall
ufw enable

# Restrict outbound connections to Wazuh only
ufw allow out to $WAZUH_HOST port 55000 comment "Wazuh Manager API"
ufw allow out to $WAZUH_INDEXER_HOST port 9200 comment "Wazuh Indexer"
```

#### Container Security Hardening

```dockerfile
# Secure Dockerfile
FROM python:3.11-slim

# Create non-root user
RUN groupadd -r wazuh && useradd -r -g wazuh -d /app -s /bin/bash wazuh

# Install security updates
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=wazuh:wazuh src/ ./src/
COPY --chown=wazuh:wazuh wazuh-mcp-server .

# Set proper permissions
RUN chmod +x wazuh-mcp-server && \
    chmod -R 755 src/

# Switch to non-root user
USER wazuh

# Security labels
LABEL security.scan="enabled"
LABEL security.non-root="true"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python3 validate-production.py --quick || exit 1

CMD ["./wazuh-mcp-server"]
```

#### Runtime Security

```bash
# Run container with security options
docker run -d \
  --name wazuh-mcp-server \
  --user 1000:1000 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  --tmpfs /var/run:rw,noexec,nosuid,size=50m \
  --security-opt=no-new-privileges:true \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  --memory=1g \
  --cpus=1.0 \
  --restart=unless-stopped \
  --env-file .env.production \
  wazuh-mcp-server:latest
```

### Application Security

#### Authentication and Authorization

```python
# Enhanced authentication configuration
AUTH_CONFIG = {
    "jwt": {
        "secret_key": os.environ["JWT_SECRET_KEY"],
        "algorithm": "HS256",
        "access_token_expire_minutes": 30,
        "refresh_token_expire_days": 7,
        "issuer": "wazuh-mcp-server",
        "audience": "mcp-clients"
    },
    "password_policy": {
        "min_length": 12,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_symbols": True,
        "forbidden_passwords": ["admin", "password", "123456"]
    },
    "rate_limiting": {
        "max_attempts": 5,
        "lockout_duration": 900,  # 15 minutes
        "window_duration": 300   # 5 minutes
    }
}
```

#### Input Validation and Sanitization

```python
# Production input validation rules
VALIDATION_RULES = {
    "agent_id": {
        "pattern": r"^[a-zA-Z0-9_-]{1,50}$",
        "max_length": 50,
        "required": True
    },
    "ip_address": {
        "pattern": r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
        "validator": "ipaddress",
        "allow_private": False
    },
    "time_range": {
        "min_value": 1,
        "max_value": 168,  # 7 days maximum
        "type": "integer"
    },
    "limit": {
        "min_value": 1,
        "max_value": 10000,
        "default": 100,
        "type": "integer"
    }
}

# SQL injection prevention patterns
BLOCKED_SQL_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE)\b)",
    r"(--|#|/\*|\*/)",
    r"(\bOR\b.*=.*)",
    r"(;.*\bEXEC\b)",
    r"(\bEXEC\b\s*\()"
]

# XSS prevention patterns
BLOCKED_XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"on\w+\s*=",
    r"<iframe[^>]*>.*?</iframe>",
    r"<object[^>]*>.*?</object>"
]
```

#### Security Monitoring

```python
# Security event logging configuration
SECURITY_EVENTS = {
    "authentication_failure": {
        "severity": "WARNING",
        "alert_threshold": 5,
        "time_window": 300
    },
    "rate_limit_exceeded": {
        "severity": "INFO", 
        "alert_threshold": 10,
        "time_window": 600
    },
    "suspicious_input": {
        "severity": "WARNING",
        "alert_threshold": 3,
        "time_window": 300
    },
    "unauthorized_access": {
        "severity": "CRITICAL",
        "alert_threshold": 1,
        "time_window": 60
    }
}

# Automated security responses
SECURITY_RESPONSES = {
    "auto_block_ip": {
        "trigger": "authentication_failure",
        "threshold": 5,
        "duration": 3600,  # 1 hour
        "action": "firewall_block"
    },
    "alert_security_team": {
        "trigger": "unauthorized_access",
        "threshold": 1,
        "action": "send_notification"
    }
}
```

---

## 📊 Monitoring and Maintenance

### Health Monitoring

#### Application Health Checks

```bash
#!/bin/bash
# health-check.sh - Comprehensive health monitoring

set -e

API_ENDPOINT="http://localhost:3000"
WAZUH_HOST=${WAZUH_HOST}
LOG_FILE="/var/log/wazuh-mcp-server/health.log"

# Function to log with timestamp
log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
}

# Check MCP server health
check_mcp_server() {
    log "Checking MCP server health..."
    
    if curl -s -f "$API_ENDPOINT/health" > /dev/null; then
        log "✅ MCP server is healthy"
        return 0
    else
        log "❌ MCP server health check failed"
        return 1
    fi
}

# Check Wazuh connectivity
check_wazuh_connectivity() {
    log "Checking Wazuh connectivity..."
    
    if curl -k -s --connect-timeout 10 "https://$WAZUH_HOST:55000/" > /dev/null; then
        log "✅ Wazuh Manager is reachable"
        return 0
    else
        log "❌ Cannot reach Wazuh Manager"
        return 1
    fi
}

# Check system resources
check_system_resources() {
    log "Checking system resources..."
    
    # Memory usage
    MEM_USAGE=$(free | grep Mem | awk '{printf("%.2f", $3/$2 * 100.0)}')
    if (( $(echo "$MEM_USAGE > 80" | bc -l) )); then
        log "⚠️  High memory usage: ${MEM_USAGE}%"
    else
        log "✅ Memory usage: ${MEM_USAGE}%"
    fi
    
    # Disk usage
    DISK_USAGE=$(df -h / | awk 'NR==2 {print $5}' | tr -d '%')
    if [ "$DISK_USAGE" -gt 80 ]; then
        log "⚠️  High disk usage: ${DISK_USAGE}%"
    else
        log "✅ Disk usage: ${DISK_USAGE}%"
    fi
    
    # CPU load
    CPU_LOAD=$(uptime | awk '{print $10}' | tr -d ',')
    log "ℹ️  CPU load: $CPU_LOAD"
}

# Check log file sizes
check_log_files() {
    log "Checking log file sizes..."
    
    LOG_DIR="/var/log/wazuh-mcp-server"
    MAX_SIZE_MB=100
    
    for log_file in "$LOG_DIR"/*.log; do
        if [ -f "$log_file" ]; then
            SIZE_MB=$(du -m "$log_file" | cut -f1)
            if [ "$SIZE_MB" -gt "$MAX_SIZE_MB" ]; then
                log "⚠️  Large log file: $(basename $log_file) - ${SIZE_MB}MB"
            fi
        fi
    done
}

# Main health check
main() {
    log "Starting health check..."
    
    HEALTH_STATUS=0
    
    check_mcp_server || HEALTH_STATUS=1
    check_wazuh_connectivity || HEALTH_STATUS=1
    check_system_resources
    check_log_files
    
    if [ $HEALTH_STATUS -eq 0 ]; then
        log "✅ Overall health check passed"
    else
        log "❌ Health check failed"
    fi
    
    return $HEALTH_STATUS
}

# Run health check
main "$@"
```

#### Prometheus Metrics Integration

```python
# metrics.py - Prometheus metrics configuration
from prometheus_client import Counter, Histogram, Gauge, start_http_server

# Define metrics
REQUEST_COUNT = Counter(
    'wazuh_mcp_requests_total',
    'Total number of requests',
    ['method', 'endpoint', 'status']
)

REQUEST_DURATION = Histogram(
    'wazuh_mcp_request_duration_seconds',
    'Request duration in seconds',
    ['method', 'endpoint']
)

ACTIVE_CONNECTIONS = Gauge(
    'wazuh_mcp_active_connections',
    'Number of active connections'
)

WAZUH_API_ERRORS = Counter(
    'wazuh_api_errors_total',
    'Total number of Wazuh API errors',
    ['error_type']
)

CACHE_HITS = Counter(
    'wazuh_mcp_cache_hits_total',
    'Total number of cache hits'
)

CACHE_MISSES = Counter(
    'wazuh_mcp_cache_misses_total',
    'Total number of cache misses'
)

# Authentication metrics
AUTH_ATTEMPTS = Counter(
    'wazuh_mcp_auth_attempts_total',
    'Total authentication attempts',
    ['result']
)

RATE_LIMIT_HITS = Counter(
    'wazuh_mcp_rate_limit_hits_total',
    'Total rate limit violations',
    ['client_ip']
)

# Start metrics server
def start_metrics_server(port=9090):
    start_http_server(port)
```

#### Grafana Dashboard Configuration

```json
{
  "dashboard": {
    "title": "Wazuh MCP Server Monitoring",
    "panels": [
      {
        "title": "Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(wazuh_mcp_requests_total[5m])",
            "legendFormat": "{{method}} {{endpoint}}"
          }
        ]
      },
      {
        "title": "Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(wazuh_mcp_request_duration_seconds_bucket[5m]))",
            "legendFormat": "95th percentile"
          }
        ]
      },
      {
        "title": "Error Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(wazuh_mcp_requests_total{status=~\"4..|5..\"}[5m])",
            "legendFormat": "Error rate"
          }
        ]
      },
      {
        "title": "Wazuh API Health",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(wazuh_api_errors_total[5m])",
            "legendFormat": "API errors/sec"
          }
        ]
      }
    ]
  }
}
```

### Log Management

#### Structured Logging Configuration

```python
# logging_config.py - Production logging configuration
import logging
import logging.handlers
import json
from datetime import datetime

class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured JSON logs."""
    
    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno
        }
        
        # Add extra fields if present
        if hasattr(record, 'extra'):
            log_entry.update(record.extra)
        
        # Add exception information if present
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        
        return json.dumps(log_entry)

def configure_logging():
    """Configure production logging."""
    
    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(StructuredFormatter())
    root_logger.addHandler(console_handler)
    
    # File handler with rotation
    file_handler = logging.handlers.RotatingFileHandler(
        "/var/log/wazuh-mcp-server/app.log",
        maxBytes=100*1024*1024,  # 100MB
        backupCount=10
    )
    file_handler.setFormatter(StructuredFormatter())
    root_logger.addHandler(file_handler)
    
    # Separate security audit log
    security_logger = logging.getLogger("security")
    security_handler = logging.handlers.RotatingFileHandler(
        "/var/log/wazuh-mcp-server/security.log",
        maxBytes=50*1024*1024,  # 50MB
        backupCount=20
    )
    security_handler.setFormatter(StructuredFormatter())
    security_logger.addHandler(security_handler)
    security_logger.setLevel(logging.INFO)
```

#### Log Aggregation with ELK Stack

```yaml
# logstash-config.yml
input {
  file {
    path => "/var/log/wazuh-mcp-server/*.log"
    codec => json
    type => "wazuh-mcp-server"
  }
}

filter {
  if [type] == "wazuh-mcp-server" {
    # Parse timestamp
    date {
      match => [ "timestamp", "ISO8601" ]
    }
    
    # Add environment tag
    mutate {
      add_tag => [ "production" ]
      add_field => { "service" => "wazuh-mcp-server" }
    }
    
    # Security event enrichment
    if [logger] == "security" {
      mutate {
        add_tag => [ "security-event" ]
      }
    }
  }
}

output {
  elasticsearch {
    hosts => ["elasticsearch:9200"]
    index => "wazuh-mcp-server-%{+YYYY.MM.dd}"
  }
}
```

---

## ⚡ Performance Optimization

### Performance Tuning Guidelines

#### Connection Pool Optimization

```python
# optimized_client_config.py
import httpx

# Production HTTP client configuration
HTTP_CLIENT_CONFIG = {
    "limits": httpx.Limits(
        max_connections=100,
        max_keepalive_connections=50,
        keepalive_expiry=30
    ),
    "timeout": httpx.Timeout(
        connect=10.0,
        read=30.0,
        write=10.0,
        pool=60.0
    ),
    "http2": True,
    "verify": True
}

# Connection pool settings
POOL_CONFIG = {
    "max_size": 50,
    "min_size": 10,
    "max_overflow": 20,
    "pool_recycle": 3600,  # 1 hour
    "pool_pre_ping": True,
    "pool_timeout": 30
}
```

#### Caching Strategy

```python
# cache_config.py - Production caching configuration

CACHE_SETTINGS = {
    "alerts": {
        "ttl": 300,  # 5 minutes
        "max_size": 1000,
        "prefetch": True
    },
    "agents": {
        "ttl": 600,  # 10 minutes
        "max_size": 5000,
        "prefetch": True
    },
    "statistics": {
        "ttl": 60,   # 1 minute
        "max_size": 100,
        "prefetch": False
    },
    "vulnerabilities": {
        "ttl": 3600, # 1 hour
        "max_size": 10000,
        "prefetch": True
    }
}

# Redis configuration for distributed caching
REDIS_CONFIG = {
    "host": "redis.company.com",
    "port": 6379,
    "db": 0,
    "password": "redis-password",
    "ssl": True,
    "max_connections": 50,
    "retry_on_timeout": True,
    "socket_keepalive": True,
    "socket_keepalive_options": {
        "TCP_KEEPIDLE": 1,
        "TCP_KEEPINTVL": 3,
        "TCP_KEEPCNT": 5
    }
}
```

#### Database Query Optimization

```python
# query_optimization.py
class OptimizedQueries:
    """Optimized query patterns for high performance."""
    
    @staticmethod
    def build_alert_query(
        limit: int = 100,
        level_threshold: int = 5,
        hours_back: int = 24
    ) -> dict:
        """Build optimized alert query."""
        
        # Calculate time range
        from datetime import datetime, timedelta
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours_back)
        
        # Optimized query with minimal fields
        query = {
            "size": min(limit, 1000),
            "from": 0,
            "_source": [
                "id", "level", "description", "timestamp",
                "rule.id", "rule.description", "agent.id", "agent.name"
            ],
            "sort": [{"timestamp": {"order": "desc"}}],
            "query": {
                "bool": {
                    "filter": [
                        {"range": {"level": {"gte": level_threshold}}},
                        {"range": {"timestamp": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat()
                        }}}
                    ]
                }
            }
        }
        
        return query
    
    @staticmethod
    def build_agent_summary_query() -> dict:
        """Build optimized agent summary query."""
        
        return {
            "size": 0,
            "aggs": {
                "status_summary": {
                    "terms": {"field": "status.keyword"}
                },
                "os_summary": {
                    "terms": {"field": "os.platform.keyword"}
                },
                "version_summary": {
                    "terms": {"field": "version.keyword"}
                }
            }
        }
```

#### Performance Monitoring

```python
# performance_monitor.py
import time
import psutil
from functools import wraps

class PerformanceMonitor:
    """Performance monitoring and alerting."""
    
    @staticmethod
    def monitor_memory_usage(threshold_mb: int = 1000):
        """Monitor memory usage and alert if exceeded."""
        
        process = psutil.Process()
        memory_mb = process.memory_info().rss / 1024 / 1024
        
        if memory_mb > threshold_mb:
            logging.warning(
                f"High memory usage: {memory_mb:.2f}MB",
                extra={"memory_mb": memory_mb, "threshold_mb": threshold_mb}
            )
        
        return memory_mb
    
    @staticmethod
    def monitor_cpu_usage(threshold_percent: float = 80.0):
        """Monitor CPU usage and alert if exceeded."""
        
        cpu_percent = psutil.cpu_percent(interval=1)
        
        if cpu_percent > threshold_percent:
            logging.warning(
                f"High CPU usage: {cpu_percent:.2f}%",
                extra={"cpu_percent": cpu_percent, "threshold_percent": threshold_percent}
            )
        
        return cpu_percent
    
    @staticmethod
    def track_response_time(func):
        """Decorator to track function response times."""
        
        @wraps(func)
        async def wrapper(*args, **kwargs):
            start_time = time.perf_counter()
            
            try:
                result = await func(*args, **kwargs)
                return result
            finally:
                end_time = time.perf_counter()
                duration = end_time - start_time
                
                # Log slow operations
                if duration > 5.0:  # 5 seconds threshold
                    logging.warning(
                        f"Slow operation: {func.__name__} took {duration:.2f}s",
                        extra={"function": func.__name__, "duration": duration}
                    )
                
                # Update metrics
                REQUEST_DURATION.labels(
                    method=func.__name__,
                    endpoint="internal"
                ).observe(duration)
        
        return wrapper
```

---

## 🔧 Troubleshooting Guide

### Common Issues and Solutions

#### Connection Issues

**Problem: Cannot connect to Wazuh Manager**

```bash
# Diagnosis steps
1. Test basic connectivity
curl -k -v https://$WAZUH_HOST:55000/

2. Check DNS resolution
nslookup $WAZUH_HOST

3. Verify port accessibility
telnet $WAZUH_HOST 55000

4. Check SSL certificate
openssl s_client -connect $WAZUH_HOST:55000 -servername $WAZUH_HOST

# Common solutions
- Verify firewall rules
- Check SSL certificate validity
- Ensure correct hostname/IP
- Verify network routing
```

**Problem: SSL certificate verification fails**

```bash
# Temporary workaround (development only)
export VERIFY_SSL=false

# Production solutions
1. Update CA certificate bundle
   cp /path/to/company-ca.crt /etc/ssl/certs/
   update-ca-certificates

2. Use custom CA bundle
   export CA_BUNDLE_PATH=/path/to/custom-ca.pem

3. Check certificate chain
   openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt /path/to/server.crt
```

#### Authentication Issues

**Problem: Authentication fails with valid credentials**

```bash
# Check user permissions
curl -k -X GET "https://$WAZUH_HOST:55000/security/users/mcp-server" \
  -H "Authorization: Bearer $JWT_TOKEN"

# Test authentication directly
curl -k -X POST "https://$WAZUH_HOST:55000/security/user/authenticate" \
  -H "Content-Type: application/json" \
  -d '{"username":"mcp-server","password":"your-password"}'

# Common causes
- User account locked
- Password expired
- Insufficient permissions
- Clock synchronization issues
```

#### Performance Issues

**Problem: Slow response times**

```bash
# Check system resources
top -p $(pgrep -f wazuh-mcp-server)
free -h
df -h

# Monitor network latency
ping $WAZUH_HOST
traceroute $WAZUH_HOST

# Database performance
curl -X GET "http://localhost:9090/metrics" | grep duration

# Solutions
1. Increase connection pool size
   MAX_CONNECTIONS=100
   POOL_SIZE=50

2. Optimize cache settings
   CACHE_TTL_SECONDS=600
   ENABLE_CACHE_PREFETCH=true

3. Tune query parameters
   MAX_ALERTS_PER_QUERY=500
   ENABLE_QUERY_OPTIMIZATION=true
```

#### Memory Issues

**Problem: High memory usage or memory leaks**

```bash
# Monitor memory usage
ps aux | grep wazuh-mcp-server
cat /proc/$(pgrep wazuh-mcp-server)/status

# Check for memory leaks
valgrind --leak-check=full python3 src/wazuh_mcp_server/main.py

# Solutions
1. Reduce cache size
   CACHE_MAX_SIZE=1000
   CACHE_TTL_SECONDS=300

2. Enable garbage collection tuning
   export PYTHONHASHSEED=random
   export PYTHONMALLOC=debug

3. Restart service periodically
   # Add to crontab
   0 2 * * * systemctl restart wazuh-mcp-server
```

### Diagnostic Tools

#### Health Check Script

```bash
#!/bin/bash
# comprehensive-diagnostics.sh

set -e

LOG_FILE="/tmp/wazuh-mcp-diagnostics-$(date +%Y%m%d-%H%M%S).log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a $LOG_FILE
}

log "🔍 Starting comprehensive diagnostics..."

# System information
log "📊 System Information"
log "OS: $(uname -a)"
log "Python: $(python3 --version)"
log "Memory: $(free -h | grep Mem)"
log "Disk: $(df -h / | tail -1)"

# Network connectivity
log "🌐 Network Connectivity"
if ping -c 3 $WAZUH_HOST > /dev/null 2>&1; then
    log "✅ Ping to Wazuh host successful"
else
    log "❌ Ping to Wazuh host failed"
fi

# Port connectivity
log "🔌 Port Connectivity"
if timeout 10 bash -c "</dev/tcp/$WAZUH_HOST/55000"; then
    log "✅ Port 55000 is accessible"
else
    log "❌ Port 55000 is not accessible"
fi

# SSL certificate check
log "🔒 SSL Certificate Check"
CERT_INFO=$(echo | openssl s_client -connect $WAZUH_HOST:55000 -servername $WAZUH_HOST 2>/dev/null | openssl x509 -noout -dates)
log "Certificate info: $CERT_INFO"

# Application status
log "🏥 Application Health"
if curl -s -f http://localhost:3000/health > /dev/null; then
    log "✅ Application health check passed"
else
    log "❌ Application health check failed"
fi

# Configuration validation
log "⚙️  Configuration Validation"
python3 validate-production.py >> $LOG_FILE 2>&1

log "📝 Diagnostics completed. Log saved to: $LOG_FILE"
```

#### Performance Profiling

```python
# profile_performance.py
import cProfile
import pstats
import io
import asyncio
from wazuh_mcp_server.api.wazuh_client import WazuhAPIClient
from wazuh_mcp_server.config import WazuhConfig

async def profile_api_calls():
    """Profile API call performance."""
    
    config = WazuhConfig.from_env()
    client = WazuhAPIClient(config)
    
    # Profile alert retrieval
    profiler = cProfile.Profile()
    profiler.enable()
    
    alerts = await client.get_alerts(limit=100)
    
    profiler.disable()
    
    # Generate profile report
    s = io.StringIO()
    ps = pstats.Stats(profiler, stream=s).sort_stats('cumulative')
    ps.print_stats()
    
    print("Performance Profile:")
    print(s.getvalue())
    
    await client.close()

if __name__ == "__main__":
    asyncio.run(profile_api_calls())
```

### Log Analysis

#### Error Pattern Detection

```bash
#!/bin/bash
# analyze-logs.sh - Automated log analysis

LOG_DIR="/var/log/wazuh-mcp-server"
REPORT_FILE="/tmp/log-analysis-$(date +%Y%m%d).txt"

echo "📊 Wazuh MCP Server Log Analysis Report" > $REPORT_FILE
echo "Generated: $(date)" >> $REPORT_FILE
echo "=======================================" >> $REPORT_FILE

# Error summary
echo "" >> $REPORT_FILE
echo "🚨 Error Summary (Last 24 hours):" >> $REPORT_FILE
grep -h "ERROR\|CRITICAL" $LOG_DIR/*.log | \
    tail -1000 | \
    cut -d' ' -f4- | \
    sort | uniq -c | sort -nr >> $REPORT_FILE

# Connection failures
echo "" >> $REPORT_FILE
echo "🔌 Connection Failures:" >> $REPORT_FILE
grep -h "Connection failed\|Timeout\|Unable to connect" $LOG_DIR/*.log | \
    tail -100 >> $REPORT_FILE

# Authentication failures
echo "" >> $REPORT_FILE
echo "🔐 Authentication Failures:" >> $REPORT_FILE
grep -h "Authentication failed\|Invalid credentials" $LOG_DIR/*.log | \
    tail -50 >> $REPORT_FILE

# Performance issues
echo "" >> $REPORT_FILE
echo "⚡ Performance Issues:" >> $REPORT_FILE
grep -h "Slow\|High.*usage\|Memory" $LOG_DIR/*.log | \
    tail -50 >> $REPORT_FILE

echo "Report saved to: $REPORT_FILE"
```

---

## 💾 Backup and Disaster Recovery

### Backup Strategy

#### Configuration Backup

```bash
#!/bin/bash
# backup-config.sh - Backup configuration and data

BACKUP_DIR="/backup/wazuh-mcp-server"
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_PATH="$BACKUP_DIR/backup-$DATE"

mkdir -p $BACKUP_PATH

echo "🗄️  Starting backup process..."

# Backup configuration files
echo "📁 Backing up configuration..."
cp -r /etc/wazuh-mcp-server/ $BACKUP_PATH/config/
cp .env.production $BACKUP_PATH/
cp docker-compose.yml $BACKUP_PATH/

# Backup logs (last 7 days)
echo "📋 Backing up logs..."
find /var/log/wazuh-mcp-server/ -name "*.log" -mtime -7 | \
    xargs tar -czf $BACKUP_PATH/logs.tar.gz

# Backup application state
echo "💾 Backing up application state..."
if [ -d "/var/lib/wazuh-mcp-server" ]; then
    tar -czf $BACKUP_PATH/appstate.tar.gz /var/lib/wazuh-mcp-server/
fi

# Backup SSL certificates
echo "🔒 Backing up SSL certificates..."
if [ -d "/etc/ssl/wazuh-mcp" ]; then
    tar -czf $BACKUP_PATH/ssl-certs.tar.gz /etc/ssl/wazuh-mcp/
fi

# Create backup manifest
echo "📝 Creating backup manifest..."
cat > $BACKUP_PATH/manifest.txt << EOF
Backup created: $(date)
Hostname: $(hostname)
Version: $(cat VERSION 2>/dev/null || echo "unknown")
Configuration files: $(ls -la $BACKUP_PATH/config/ | wc -l) files
Logs: $(stat -c%s $BACKUP_PATH/logs.tar.gz 2>/dev/null || echo "0") bytes
SSL certificates: $(stat -c%s $BACKUP_PATH/ssl-certs.tar.gz 2>/dev/null || echo "0") bytes
EOF

# Compress entire backup
cd $BACKUP_DIR
tar -czf "backup-$DATE.tar.gz" "backup-$DATE/"
rm -rf "backup-$DATE/"

echo "✅ Backup completed: $BACKUP_DIR/backup-$DATE.tar.gz"

# Cleanup old backups (keep last 30 days)
find $BACKUP_DIR -name "backup-*.tar.gz" -mtime +30 -delete

echo "🧹 Old backups cleaned up"
```

#### Automated Backup Schedule

```bash
# /etc/cron.d/wazuh-mcp-backup
# Daily backup at 2 AM
0 2 * * * root /opt/wazuh-mcp-server/scripts/backup-config.sh

# Weekly full backup on Sunday at 3 AM
0 3 * * 0 root /opt/wazuh-mcp-server/scripts/full-backup.sh

# Monthly backup verification on first day at 4 AM
0 4 1 * * root /opt/wazuh-mcp-server/scripts/verify-backups.sh
```

### Disaster Recovery

#### Recovery Procedures

```bash
#!/bin/bash
# disaster-recovery.sh - Disaster recovery procedures

BACKUP_FILE=${1}
RECOVERY_DIR="/opt/wazuh-mcp-server-recovery"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup-file.tar.gz>"
    exit 1
fi

echo "🚑 Starting disaster recovery process..."

# Create recovery directory
mkdir -p $RECOVERY_DIR
cd $RECOVERY_DIR

# Extract backup
echo "📦 Extracting backup..."
tar -xzf $BACKUP_FILE

BACKUP_DIR=$(ls -1 | grep backup- | head -1)
cd $BACKUP_DIR

# Restore configuration
echo "⚙️  Restoring configuration..."
if [ -d "config" ]; then
    sudo cp -r config/* /etc/wazuh-mcp-server/
    sudo cp .env.production /opt/wazuh-mcp-server/
fi

# Restore SSL certificates
echo "🔒 Restoring SSL certificates..."
if [ -f "ssl-certs.tar.gz" ]; then
    sudo tar -xzf ssl-certs.tar.gz -C /
fi

# Restore application state
echo "💾 Restoring application state..."
if [ -f "appstate.tar.gz" ]; then
    sudo tar -xzf appstate.tar.gz -C /
fi

# Set proper permissions
echo "🔧 Setting permissions..."
sudo chown -R wazuh:wazuh /opt/wazuh-mcp-server/
sudo chmod 600 /opt/wazuh-mcp-server/.env.production

# Validate configuration
echo "✅ Validating configuration..."
cd /opt/wazuh-mcp-server
python3 validate-production.py

# Restart services
echo "🔄 Restarting services..."
sudo systemctl restart wazuh-mcp-server
sudo systemctl status wazuh-mcp-server

echo "🎉 Disaster recovery completed!"
echo "Please verify functionality and monitor logs"
```

#### Business Continuity Planning

**RTO (Recovery Time Objective): 30 minutes**
**RPO (Recovery Point Objective): 24 hours**

**Recovery Scenarios:**

1. **Server Hardware Failure**
   - Deploy to backup server
   - Restore from latest backup
   - Update DNS/load balancer

2. **Data Center Outage**
   - Activate secondary data center
   - Restore services from cloud backup
   - Redirect traffic via global load balancer

3. **Wazuh Infrastructure Failure**
   - Switch to backup Wazuh cluster
   - Update configuration
   - Validate connectivity

4. **Complete Service Failure**
   - Deploy fresh instance
   - Restore from backup
   - Perform full validation

### High Availability Setup

#### Multi-Site Deployment

```yaml
# ha-deployment.yml - High availability deployment
version: '3.8'
services:
  wazuh-mcp-primary:
    image: wazuh-mcp-server:latest
    environment:
      - SITE=primary
      - CLUSTER_MODE=true
    deploy:
      replicas: 2
      placement:
        constraints:
          - node.labels.site == primary

  wazuh-mcp-secondary:
    image: wazuh-mcp-server:latest
    environment:
      - SITE=secondary
      - CLUSTER_MODE=true
    deploy:
      replicas: 2
      placement:
        constraints:
          - node.labels.site == secondary

  keepalived:
    image: osixia/keepalived:latest
    network_mode: host
    cap_add:
      - NET_ADMIN
    environment:
      - KEEPALIVED_INTERFACE=eth0
      - KEEPALIVED_VIRTUAL_IPS=192.168.1.100
      - KEEPALIVED_UNICAST_PEERS=#PYTHON2BASH:['192.168.1.10', '192.168.1.11']
```

#### Automated Failover

```bash
#!/bin/bash
# failover-monitor.sh - Automated failover monitoring

PRIMARY_HOST="wazuh-mcp-primary.company.com"
SECONDARY_HOST="wazuh-mcp-secondary.company.com"
HEALTH_ENDPOINT="/health"
CHECK_INTERVAL=30

while true; do
    # Check primary health
    if curl -s -f "http://$PRIMARY_HOST$HEALTH_ENDPOINT" > /dev/null; then
        echo "$(date): Primary is healthy"
    else
        echo "$(date): Primary is down, initiating failover..."
        
        # Trigger failover
        # 1. Update load balancer
        # 2. Promote secondary
        # 3. Alert operations team
        
        curl -X POST "http://loadbalancer/api/failover" \
            -d '{"primary": "'$SECONDARY_HOST'", "backup": "'$PRIMARY_HOST'"}'
        
        # Send alert
        curl -X POST "$SLACK_WEBHOOK" \
            -d '{"text": "Wazuh MCP Server failover activated - Primary down"}'
    fi
    
    sleep $CHECK_INTERVAL
done
```

---

## 📋 Compliance and Auditing

### Compliance Framework Support

#### SOC 2 Type II Compliance

**Security Controls:**
- Multi-factor authentication
- Role-based access control
- Audit logging and monitoring
- Encryption in transit and at rest
- Regular security assessments

```python
# compliance_controls.py
class SOC2Controls:
    """SOC 2 Type II compliance controls."""
    
    @staticmethod
    def audit_access_controls():
        """Audit access control implementation."""
        controls = {
            "CC6.1": "Logical access controls",
            "CC6.2": "Authentication mechanisms", 
            "CC6.3": "Authorization mechanisms",
            "CC6.6": "Logical access removal",
            "CC6.7": "Access review procedures"
        }
        
        # Verify implementation
        results = {}
        for control_id, description in controls.items():
            results[control_id] = verify_control(control_id)
        
        return results
    
    @staticmethod
    def generate_audit_report():
        """Generate compliance audit report."""
        report = {
            "timestamp": datetime.utcnow().isoformat(),
            "compliance_framework": "SOC 2 Type II",
            "controls": SOC2Controls.audit_access_controls(),
            "recommendations": [],
            "risk_level": "LOW"
        }
        
        return report
```

#### NIST Cybersecurity Framework

**Implementation Mapping:**

```yaml
# nist-csf-mapping.yml
framework: "NIST Cybersecurity Framework v1.1"
implementation:
  identify:
    - id: "ID.AM-1"
      description: "Physical devices and systems within the organization are inventoried"
      implementation: "Agent inventory and monitoring via Wazuh integration"
      status: "Implemented"
    
    - id: "ID.AM-2" 
      description: "Software platforms and applications within the organization are inventoried"
      implementation: "Software inventory via Wazuh syscollector"
      status: "Implemented"

  protect:
    - id: "PR.AC-1"
      description: "Identities and credentials are issued, managed, verified, revoked, and audited"
      implementation: "JWT-based authentication with audit logging"
      status: "Implemented"
    
    - id: "PR.AC-4"
      description: "Access permissions and authorizations are managed"
      implementation: "Role-based access control with minimal privileges"
      status: "Implemented"

  detect:
    - id: "DE.AE-1"
      description: "A baseline of network operations and expected data flows is established"
      implementation: "Wazuh network monitoring and baseline detection"
      status: "Implemented"

  respond:
    - id: "RS.RP-1"
      description: "Response plan is executed during or after an incident"
      implementation: "Automated incident response via MCP tools"
      status: "Implemented"

  recover:
    - id: "RC.RP-1"
      description: "Recovery plan is executed during or after a cybersecurity incident"
      implementation: "Disaster recovery procedures and backup restoration"
      status: "Implemented"
```

### Audit Logging

#### Comprehensive Audit Trail

```python
# audit_logger.py
import logging
import json
from datetime import datetime
from typing import Dict, Any, Optional

class AuditLogger:
    """Comprehensive audit logging for compliance."""
    
    def __init__(self):
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(logging.INFO)
        
        # Separate audit log file
        handler = logging.FileHandler("/var/log/wazuh-mcp-server/audit.log")
        formatter = logging.Formatter('%(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
    
    def log_authentication(
        self,
        user_id: str,
        action: str,
        result: str,
        ip_address: str,
        user_agent: str,
        additional_data: Optional[Dict[str, Any]] = None
    ):
        """Log authentication events."""
        
        audit_entry = {
            "event_type": "authentication",
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "action": action,
            "result": result,
            "source_ip": ip_address,
            "user_agent": user_agent,
            "session_id": self._get_session_id(),
            "additional_data": additional_data or {}
        }
        
        self.logger.info(json.dumps(audit_entry))
    
    def log_api_access(
        self,
        user_id: str,
        endpoint: str,
        method: str,
        parameters: Dict[str, Any],
        response_status: int,
        response_size: int,
        duration: float
    ):
        """Log API access events."""
        
        audit_entry = {
            "event_type": "api_access",
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "endpoint": endpoint,
            "method": method,
            "parameters": self._sanitize_parameters(parameters),
            "response_status": response_status,
            "response_size": response_size,
            "duration": duration,
            "correlation_id": self._get_correlation_id()
        }
        
        self.logger.info(json.dumps(audit_entry))
    
    def log_security_event(
        self,
        event_type: str,
        severity: str,
        description: str,
        user_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        affected_resources: Optional[list] = None
    ):
        """Log security events."""
        
        audit_entry = {
            "event_type": "security",
            "timestamp": datetime.utcnow().isoformat(),
            "security_event_type": event_type,
            "severity": severity,
            "description": description,
            "user_id": user_id,
            "source_ip": source_ip,
            "affected_resources": affected_resources or [],
            "remediation_status": "pending"
        }
        
        self.logger.info(json.dumps(audit_entry))
    
    def log_configuration_change(
        self,
        user_id: str,
        change_type: str,
        configuration_item: str,
        old_value: Any,
        new_value: Any,
        reason: str
    ):
        """Log configuration changes."""
        
        audit_entry = {
            "event_type": "configuration_change",
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "change_type": change_type,
            "configuration_item": configuration_item,
            "old_value": self._sanitize_value(old_value),
            "new_value": self._sanitize_value(new_value),
            "reason": reason,
            "approval_status": "auto_approved"
        }
        
        self.logger.info(json.dumps(audit_entry))
    
    def _sanitize_parameters(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize sensitive parameters for logging."""
        sensitive_keys = {"password", "token", "secret", "key"}
        
        sanitized = {}
        for key, value in params.items():
            if any(sensitive in key.lower() for sensitive in sensitive_keys):
                sanitized[key] = "***redacted***"
            else:
                sanitized[key] = value
        
        return sanitized
    
    def _sanitize_value(self, value: Any) -> Any:
        """Sanitize sensitive values for logging."""
        if isinstance(value, str) and len(value) > 50:
            return value[:50] + "..."
        return value
    
    def _get_session_id(self) -> str:
        """Get current session ID."""
        # Implementation depends on session management
        return "session_123"
    
    def _get_correlation_id(self) -> str:
        """Get correlation ID for request tracking."""
        # Implementation depends on request tracking
        return "corr_456"
```

#### Audit Report Generation

```python
# audit_reporter.py
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any

class AuditReporter:
    """Generate compliance audit reports."""
    
    def __init__(self, audit_log_path: str = "/var/log/wazuh-mcp-server/audit.log"):
        self.audit_log_path = audit_log_path
    
    def generate_compliance_report(
        self,
        start_date: datetime,
        end_date: datetime,
        report_type: str = "monthly"
    ) -> Dict[str, Any]:
        """Generate comprehensive compliance report."""
        
        audit_events = self._parse_audit_log(start_date, end_date)
        
        report = {
            "report_metadata": {
                "type": report_type,
                "period": {
                    "start": start_date.isoformat(),
                    "end": end_date.isoformat()
                },
                "generated": datetime.utcnow().isoformat(),
                "total_events": len(audit_events)
            },
            "authentication_summary": self._analyze_authentication(audit_events),
            "api_access_summary": self._analyze_api_access(audit_events),
            "security_events": self._analyze_security_events(audit_events),
            "configuration_changes": self._analyze_configuration_changes(audit_events),
            "compliance_metrics": self._calculate_compliance_metrics(audit_events),
            "recommendations": self._generate_recommendations(audit_events)
        }
        
        return report
    
    def _parse_audit_log(self, start_date: datetime, end_date: datetime) -> List[Dict[str, Any]]:
        """Parse audit log for specified date range."""
        events = []
        
        try:
            with open(self.audit_log_path, 'r') as f:
                for line in f:
                    try:
                        event = json.loads(line.strip())
                        event_time = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                        
                        if start_date <= event_time <= end_date:
                            events.append(event)
                    except (json.JSONDecodeError, KeyError, ValueError):
                        continue
        except FileNotFoundError:
            pass
        
        return events
    
    def _analyze_authentication(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze authentication events."""
        auth_events = [e for e in events if e.get('event_type') == 'authentication']
        
        successful_logins = len([e for e in auth_events if e.get('result') == 'success'])
        failed_logins = len([e for e in auth_events if e.get('result') == 'failure'])
        
        return {
            "total_attempts": len(auth_events),
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "success_rate": successful_logins / len(auth_events) if auth_events else 0,
            "unique_users": len(set(e.get('user_id') for e in auth_events if e.get('user_id'))),
            "suspicious_activity": failed_logins > 10
        }
    
    def _analyze_security_events(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze security events."""
        security_events = [e for e in events if e.get('event_type') == 'security']
        
        severity_counts = {}
        event_types = {}
        
        for event in security_events:
            severity = event.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            sec_event_type = event.get('security_event_type', 'unknown')
            event_types[sec_event_type] = event_types.get(sec_event_type, 0) + 1
        
        return {
            "total_security_events": len(security_events),
            "severity_distribution": severity_counts,
            "event_type_distribution": event_types,
            "critical_events": len([e for e in security_events if e.get('severity') == 'CRITICAL'])
        }
    
    def _calculate_compliance_metrics(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate compliance metrics."""
        total_events = len(events)
        
        # Access control metrics
        auth_events = [e for e in events if e.get('event_type') == 'authentication']
        successful_auth_rate = len([e for e in auth_events if e.get('result') == 'success']) / len(auth_events) if auth_events else 0
        
        # Audit coverage
        event_types = set(e.get('event_type') for e in events)
        required_event_types = {'authentication', 'api_access', 'security', 'configuration_change'}
        audit_coverage = len(event_types.intersection(required_event_types)) / len(required_event_types)
        
        return {
            "audit_completeness": audit_coverage,
            "authentication_effectiveness": successful_auth_rate,
            "incident_response_time": "< 15 minutes",  # Based on monitoring
            "data_retention_compliance": True,
            "encryption_coverage": 100.0
        }
```

### Compliance Reporting

#### Automated Report Generation

```bash
#!/bin/bash
# generate-compliance-report.sh

REPORT_DIR="/var/reports/wazuh-mcp-server"
DATE=$(date +%Y%m%d)
REPORT_TYPE=${1:-monthly}

mkdir -p $REPORT_DIR

echo "📊 Generating $REPORT_TYPE compliance report..."

# Generate audit report
python3 << EOF
from audit_reporter import AuditReporter
from datetime import datetime, timedelta
import json

reporter = AuditReporter()

if "$REPORT_TYPE" == "monthly":
    end_date = datetime.now()
    start_date = end_date - timedelta(days=30)
elif "$REPORT_TYPE" == "weekly":
    end_date = datetime.now()
    start_date = end_date - timedelta(days=7)
else:
    end_date = datetime.now()
    start_date = end_date - timedelta(days=1)

report = reporter.generate_compliance_report(start_date, end_date, "$REPORT_TYPE")

with open("$REPORT_DIR/compliance-report-$DATE.json", "w") as f:
    json.dump(report, f, indent=2)

print("Report generated successfully")
EOF

# Convert to PDF (optional)
if command -v pandoc &> /dev/null; then
    pandoc "$REPORT_DIR/compliance-report-$DATE.json" \
        -o "$REPORT_DIR/compliance-report-$DATE.pdf"
fi

echo "✅ Compliance report generated: $REPORT_DIR/compliance-report-$DATE.json"

# Send to compliance team (if configured)
if [ ! -z "$COMPLIANCE_EMAIL" ]; then
    echo "📧 Sending report to compliance team..."
    mail -s "Wazuh MCP Server Compliance Report - $DATE" \
        -a "$REPORT_DIR/compliance-report-$DATE.json" \
        "$COMPLIANCE_EMAIL" < /dev/null
fi
```

---

**🎉 Congratulations! You now have a comprehensive guide for deploying and managing Wazuh MCP Server in production environments. This guide ensures security, compliance, and operational excellence.**

**For additional support, refer to:**
- **Technical Documentation**: `DEVELOPER_GUIDE.md`
- **Security Guidelines**: `docs/security-guide.md`
- **Troubleshooting**: `docs/troubleshooting.md`
- **Community Support**: GitHub Issues and Discussions