# Production Deployment Guide - Wazuh MCP Server v3.0.0

## Overview

This guide provides comprehensive instructions for deploying Wazuh MCP Server v3.0.0 in production environments with high availability, security hardening, and monitoring.

## Pre-Deployment Checklist

### System Requirements

#### Hardware Requirements
- **CPU**: 4+ cores (8+ recommended for high availability)
- **RAM**: 8GB minimum (16GB+ recommended)
- **Storage**: 100GB minimum (500GB+ recommended with monitoring stack)
- **Network**: 1Gbps network interface

#### Software Requirements
- **Operating System**: Linux (Ubuntu 20.04+, CentOS 8+, RHEL 8+)
- **Docker**: Version 20.10+ with Docker Compose v2.0+
- **Python**: 3.9+ (for development/testing)
- **Wazuh Manager**: 4.8+ with API access
- **SSL Certificates**: Valid SSL certificates for HTTPS

### Security Requirements

#### Network Security
- **Firewall**: Configured to allow only necessary ports
- **SSL/TLS**: Valid certificates for all HTTPS endpoints
- **Network Segmentation**: Isolated network for security services
- **VPN Access**: Secure remote access for administration

#### Authentication
- **Strong Passwords**: Enforce password complexity
- **API Keys**: Secure generation and storage
- **OAuth2 Secrets**: Cryptographically secure client secrets
- **JWT Tokens**: Secure key generation and rotation

## Production Deployment Options

### Option 1: High Availability Docker Compose (Recommended)

#### Step 1: Environment Preparation

```bash
# Create deployment directory
mkdir -p /opt/wazuh-mcp-server
cd /opt/wazuh-mcp-server

# Clone repository
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git .

# Set proper permissions
chmod +x scripts/*.sh
```

#### Step 2: Security Configuration

```bash
# Generate secure secrets
export JWT_SECRET=$(openssl rand -base64 32)
export OAUTH_CLIENT_SECRET=$(openssl rand -base64 32)
export REDIS_PASSWORD=$(openssl rand -base64 32)

# Create production environment file
cat > .env << EOF
# Wazuh Configuration
WAZUH_API_URL=https://your-wazuh-manager:55000
WAZUH_API_USERNAME=wazuh-mcp-api
WAZUH_API_PASSWORD=your-secure-password
WAZUH_API_VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=false

# Server Configuration
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8443
MCP_TRANSPORT=sse
ENVIRONMENT=production

# Authentication
OAUTH_ENABLED=true
JWT_SECRET_KEY=${JWT_SECRET}
OAUTH_CLIENT_ID=wazuh-mcp-client
OAUTH_CLIENT_SECRET=${OAUTH_CLIENT_SECRET}

# Database
REDIS_HOST=redis
REDIS_PORT=6379
REDIS_PASSWORD=${REDIS_PASSWORD}

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090
PROMETHEUS_RETENTION_TIME=15d

# Logging
LOG_LEVEL=INFO
LOG_FORMAT=json
ENABLE_AUDIT_LOG=true

# SSL/TLS
SSL_CERT_PATH=/certs/server.crt
SSL_KEY_PATH=/certs/server.key
SSL_CA_PATH=/certs/ca.crt

# Backup
BACKUP_ENABLED=true
BACKUP_S3_BUCKET=wazuh-mcp-backups
BACKUP_RETENTION_DAYS=30
EOF

# Secure environment file
chmod 600 .env
```

#### Step 3: SSL Certificate Setup

```bash
# Create certificate directory
mkdir -p /opt/wazuh-mcp-server/certs

# Option 1: Use existing certificates
cp /path/to/your/server.crt /opt/wazuh-mcp-server/certs/
cp /path/to/your/server.key /opt/wazuh-mcp-server/certs/
cp /path/to/your/ca.crt /opt/wazuh-mcp-server/certs/

# Option 2: Generate self-signed certificates (development only)
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes \
  -subj "/CN=your-server-fqdn"

# Set proper permissions
chmod 600 certs/server.key
chmod 644 certs/server.crt
```

#### Step 4: Deploy Production Stack

```bash
# Deploy high availability stack
docker compose -f docker compose.ha.yml up -d

# Verify deployment
docker compose -f docker compose.ha.yml ps
```

#### Step 5: Post-Deployment Verification

```bash
# Check service health
curl -f https://localhost:8443/health

# Check monitoring stack
curl -f http://localhost:9090/metrics
curl -f http://localhost:3000  # Grafana

# Check load balancer
curl -f http://localhost:80/stats

# Run validation script
python scripts/validate_setup.py --production
```

### Option 2: Kubernetes Deployment

#### Step 1: Prepare Kubernetes Manifests

```bash
# Create namespace
kubectl create namespace wazuh-mcp-server

# Create secrets
kubectl create secret generic wazuh-mcp-secrets \
  --from-literal=jwt-secret=$(openssl rand -base64 32) \
  --from-literal=oauth-client-secret=$(openssl rand -base64 32) \
  --from-literal=redis-password=$(openssl rand -base64 32) \
  --from-literal=wazuh-api-password=your-secure-password \
  -n wazuh-mcp-server

# Create TLS secret for certificates
kubectl create secret tls wazuh-mcp-tls \
  --cert=/path/to/server.crt \
  --key=/path/to/server.key \
  -n wazuh-mcp-server
```

#### Step 2: Deploy Services

```bash
# Deploy all services
kubectl apply -f k8s/ -n wazuh-mcp-server

# Check deployment status
kubectl get pods -n wazuh-mcp-server
kubectl get services -n wazuh-mcp-server
```

### Option 3: Manual Installation

#### Step 1: System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv nginx redis-server postgresql-client

# Create service user
sudo useradd -r -s /bin/false wazuh-mcp-server
sudo mkdir -p /opt/wazuh-mcp-server
sudo chown wazuh-mcp-server:wazuh-mcp-server /opt/wazuh-mcp-server
```

#### Step 2: Application Installation

```bash
# Switch to service user
sudo -u wazuh-mcp-server -i

# Clone and setup
cd /opt/wazuh-mcp-server
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git .

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure environment
cp .env.example .env
# Edit .env with your configuration
```

#### Step 3: System Service Configuration

```bash
# Create systemd service file
sudo tee /etc/systemd/system/wazuh-mcp-server.service << EOF
[Unit]
Description=Wazuh MCP Server
After=network.target redis.service

[Service]
Type=simple
User=wazuh-mcp-server
Group=wazuh-mcp-server
WorkingDirectory=/opt/wazuh-mcp-server
Environment=PATH=/opt/wazuh-mcp-server/venv/bin
ExecStart=/opt/wazuh-mcp-server/venv/bin/python -m wazuh_mcp_server.remote_server
Restart=always
RestartSec=10
KillMode=process
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable wazuh-mcp-server
sudo systemctl start wazuh-mcp-server
```

## Security Hardening

### Network Security

#### Firewall Configuration

```bash
# Allow only necessary ports
sudo ufw allow 22/tcp      # SSH
sudo ufw allow 80/tcp      # HTTP (redirect to HTTPS)
sudo ufw allow 443/tcp     # HTTPS
sudo ufw allow 8443/tcp    # MCP Server
sudo ufw allow 9090/tcp    # Metrics (internal only)

# Enable firewall
sudo ufw enable
```

#### Nginx Reverse Proxy

```bash
# Install nginx
sudo apt install -y nginx

# Configure SSL termination
sudo tee /etc/nginx/sites-available/wazuh-mcp-server << 'EOF'
server {
    listen 80;
    server_name your-server-fqdn;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-server-fqdn;

    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;

    # Security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains";

    location / {
        proxy_pass http://localhost:8443;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # SSE specific headers
        proxy_set_header Connection '';
        proxy_http_version 1.1;
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
EOF

# Enable site
sudo ln -s /etc/nginx/sites-available/wazuh-mcp-server /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Application Security

#### OAuth2 Client Management

```bash
# Create OAuth2 client
python3 -c "
import sys
sys.path.insert(0, '/opt/wazuh-mcp-server/src')
from wazuh_mcp_server.auth.oauth2 import OAuth2Manager
from wazuh_mcp_server.auth.models import OAuth2Client

oauth = OAuth2Manager()
client = oauth.create_client(
    client_id='wazuh-mcp-client',
    client_secret='your-secure-client-secret',
    redirect_uris=['https://your-client-app/callback'],
    scopes=['read:alerts', 'read:agents', 'read:vulnerabilities']
)
print(f'Created client: {client.client_id}')
"
```

#### User Management

```bash
# Create admin user
python3 -c "
import sys
sys.path.insert(0, '/opt/wazuh-mcp-server/src')
from wazuh_mcp_server.auth.models import User

user = User.create_user(
    username='admin',
    password='your-secure-password',
    email='admin@your-domain.com',
    scopes=['admin:*']
)
print(f'Created admin user: {user.username}')
"
```

## Monitoring and Observability

### Prometheus Configuration

The production deployment includes comprehensive monitoring:

#### Key Metrics
- **Server Health**: Uptime, response times, error rates
- **Authentication**: Login attempts, token validation
- **Wazuh Integration**: API response times, error rates
- **System Resources**: CPU, memory, disk usage
- **Network**: Connection counts, request rates

#### Alerting Rules
- **Critical Alerts**: Server down, authentication failures
- **High Priority**: High response times, resource exhaustion
- **Medium Priority**: Increased error rates, capacity warnings
- **Low Priority**: Performance degradation, maintenance needs

### Grafana Dashboards

Access Grafana at `http://localhost:3000` (default: admin/admin)

#### Available Dashboards
- **System Overview**: Server health and performance
- **Security Dashboard**: Authentication and security events
- **Wazuh Integration**: API performance and error tracking
- **Business Metrics**: Request volumes and user activity

### Log Management

#### Centralized Logging

```bash
# Configure rsyslog for centralized logging
sudo tee -a /etc/rsyslog.conf << 'EOF'
# Wazuh MCP Server logs
local0.*    /var/log/wazuh-mcp-server/application.log
local1.*    /var/log/wazuh-mcp-server/security.log
local2.*    /var/log/wazuh-mcp-server/audit.log
EOF

sudo systemctl restart rsyslog
```

#### Log Rotation

```bash
# Configure log rotation
sudo tee /etc/logrotate.d/wazuh-mcp-server << 'EOF'
/var/log/wazuh-mcp-server/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 wazuh-mcp-server wazuh-mcp-server
    postrotate
        systemctl reload wazuh-mcp-server
    endscript
}
EOF
```

## Backup and Recovery

### Automated Backup Setup

```bash
# Create backup script
sudo tee /opt/wazuh-mcp-server/scripts/backup.sh << 'EOF'
#!/bin/bash
set -euo pipefail

BACKUP_DIR="/opt/backups/wazuh-mcp-server"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="wazuh-mcp-server_${TIMESTAMP}.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup configuration and certificates
tar -czf "$BACKUP_DIR/$BACKUP_FILE" \
    --exclude=venv \
    --exclude=logs \
    --exclude=__pycache__ \
    /opt/wazuh-mcp-server/

# Backup database if using PostgreSQL
if [ -n "${POSTGRES_DB:-}" ]; then
    pg_dump -h localhost -U wazuh_mcp_server -d wazuh_mcp_server > "$BACKUP_DIR/database_${TIMESTAMP}.sql"
fi

# Upload to S3 if configured
if [ -n "${AWS_S3_BUCKET:-}" ]; then
    aws s3 cp "$BACKUP_DIR/$BACKUP_FILE" "s3://${AWS_S3_BUCKET}/backups/"
fi

# Cleanup old backups (keep 30 days)
find "$BACKUP_DIR" -type f -mtime +30 -delete

echo "Backup completed: $BACKUP_FILE"
EOF

chmod +x /opt/wazuh-mcp-server/scripts/backup.sh
```

### Scheduled Backups

```bash
# Add to crontab
sudo crontab -e
# Add this line for daily backups at 2 AM
0 2 * * * /opt/wazuh-mcp-server/scripts/backup.sh
```

### Disaster Recovery

```bash
# Recovery script
sudo tee /opt/wazuh-mcp-server/scripts/restore.sh << 'EOF'
#!/bin/bash
set -euo pipefail

BACKUP_FILE="$1"
RESTORE_DIR="/opt/wazuh-mcp-server"

if [ ! -f "$BACKUP_FILE" ]; then
    echo "Backup file not found: $BACKUP_FILE"
    exit 1
fi

# Stop services
sudo systemctl stop wazuh-mcp-server nginx

# Restore files
sudo tar -xzf "$BACKUP_FILE" -C /

# Restore database if needed
if [ -f "${BACKUP_FILE%.tar.gz}_database.sql" ]; then
    psql -h localhost -U wazuh_mcp_server -d wazuh_mcp_server < "${BACKUP_FILE%.tar.gz}_database.sql"
fi

# Set permissions
sudo chown -R wazuh-mcp-server:wazuh-mcp-server /opt/wazuh-mcp-server

# Start services
sudo systemctl start wazuh-mcp-server nginx

echo "Recovery completed"
EOF

chmod +x /opt/wazuh-mcp-server/scripts/restore.sh
```

## Performance Optimization

### Database Optimization

```bash
# Redis configuration for production
sudo tee -a /etc/redis/redis.conf << 'EOF'
# Memory optimization
maxmemory 2gb
maxmemory-policy allkeys-lru

# Persistence
save 900 1
save 300 10
save 60 10000

# Security
requirepass your-redis-password
EOF

sudo systemctl restart redis
```

### Application Tuning

```bash
# Optimize Python process
export PYTHONUNBUFFERED=1
export PYTHONOPTIMIZE=1

# Increase file descriptor limits
sudo tee -a /etc/security/limits.conf << 'EOF'
wazuh-mcp-server soft nofile 65536
wazuh-mcp-server hard nofile 65536
EOF
```

## Maintenance Procedures

### Regular Maintenance Tasks

#### Daily Tasks
- Monitor system health via Grafana dashboards
- Check application logs for errors
- Verify backup completion
- Review security alerts

#### Weekly Tasks
- Update system packages
- Rotate log files
- Review performance metrics
- Check SSL certificate expiration

#### Monthly Tasks
- Update application dependencies
- Review and update security policies
- Perform disaster recovery testing
- Update documentation

### Update Procedures

```bash
# Application updates
cd /opt/wazuh-mcp-server
sudo -u wazuh-mcp-server -i

# Backup current version
cp -r /opt/wazuh-mcp-server /opt/wazuh-mcp-server.backup

# Update code
git pull origin main

# Update dependencies
source venv/bin/activate
pip install -r requirements.txt

# Run tests
python -m pytest tests/

# Restart services
sudo systemctl restart wazuh-mcp-server
```

## Troubleshooting

### Common Issues

#### Service Not Starting
```bash
# Check service status
sudo systemctl status wazuh-mcp-server

# Check logs
sudo journalctl -u wazuh-mcp-server -f

# Check application logs
tail -f /var/log/wazuh-mcp-server/application.log
```

#### Authentication Issues
```bash
# Test OAuth2 endpoint
curl -X POST https://localhost:8443/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=wazuh-mcp-client&client_secret=your-secret"

# Check user permissions
python3 -c "
from wazuh_mcp_server.auth.models import User
user = User.get_by_username('admin')
print(f'User scopes: {user.scopes}')
"
```

#### Performance Issues
```bash
# Check system resources
htop
iostat -x 1

# Check application metrics
curl http://localhost:9090/metrics

# Check database performance
redis-cli info
```

### Emergency Procedures

#### Service Recovery
```bash
# Quick restart
sudo systemctl restart wazuh-mcp-server nginx redis

# Full recovery
sudo systemctl stop wazuh-mcp-server
sudo systemctl start wazuh-mcp-server
```

#### Security Incident Response
```bash
# Disable authentication temporarily
export OAUTH_ENABLED=false
sudo systemctl restart wazuh-mcp-server

# Check for unauthorized access
grep "authentication_failed" /var/log/wazuh-mcp-server/security.log

# Rotate JWT secrets
python3 scripts/rotate_jwt_secrets.py
```

## Support and Escalation

### Support Channels
- **GitHub Issues**: [Report technical issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Documentation**: [Complete documentation](https://docs.wazuh-mcp-server.org)
- **Security Issues**: [Security reporting](SECURITY.md)

### Escalation Matrix
- **Level 1**: Application issues, configuration problems
- **Level 2**: Performance issues, integration problems
- **Level 3**: Security incidents, data corruption
- **Level 4**: System-wide outages, disaster recovery

This production deployment guide provides a comprehensive foundation for running Wazuh MCP Server v3.0.0 in production environments. Regular monitoring, maintenance, and security updates are essential for optimal performance and security.