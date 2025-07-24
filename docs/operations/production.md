# Production Deployment Guide

## Overview

This guide covers deploying Wazuh MCP Server in production environments with security, reliability, and performance best practices.

## Deployment Options

### Docker Deployment (Recommended)

```bash
# 1. Clone and configure
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
cp .env.production .env
vim .env  # Configure credentials

# 2. Deploy
./scripts/deploy-production.sh

# 3. Verify
./scripts/test-deployment.sh
```

### Manual Deployment

```bash
# 1. System setup
sudo useradd -r -s /bin/false wazuh-mcp
sudo mkdir -p /opt/wazuh-mcp-server
sudo chown wazuh-mcp:wazuh-mcp /opt/wazuh-mcp-server

# 2. Install application
cd /opt/wazuh-mcp-server
sudo -u wazuh-mcp python -m venv venv
sudo -u wazuh-mcp venv/bin/pip install -r requirements-prod.txt

# 3. Configure systemd
sudo cp scripts/wazuh-mcp.service /etc/systemd/system/
sudo systemctl enable wazuh-mcp
sudo systemctl start wazuh-mcp
```

## Production Configuration

### Environment Variables

```bash
# Required
WAZUH_API_URL=https://wazuh.internal:55000
WAZUH_API_USERNAME=mcp-api-user
WAZUH_API_PASSWORD=secure-password

# Production settings
MCP_SERVER_MODE=remote
MCP_SERVER_PORT=8443
LOG_LEVEL=WARNING
OAUTH_ENABLED=true
JWT_SECRET_KEY=<generate-strong-key>

# Performance
MAX_CONNECTIONS=1000
WORKER_PROCESSES=4
REQUEST_TIMEOUT=30
```

### SSL Certificate

```bash
# Generate production certificate
openssl req -x509 -newkey rsa:4096 \
  -keyout /app/config/ssl/key.pem \
  -out /app/config/ssl/cert.pem \
  -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=wazuh-mcp.internal"
```

## Security Hardening

### Network Security

```yaml
# docker-compose.yml additions
services:
  wazuh-mcp-server:
    networks:
      - internal
    ports:
      - "127.0.0.1:8443:8443"  # Bind to localhost only
```

### Firewall Rules

```bash
# Allow only from specific subnets
sudo ufw allow from 10.0.0.0/24 to any port 8443
sudo ufw allow from 192.168.1.0/24 to any port 8443
```

### Authentication

1. **Create API User in Wazuh:**
   ```bash
   curl -u admin:admin -k -X POST \
     "https://wazuh:55000/security/users" \
     -H "Content-Type: application/json" \
     -d '{
       "username": "mcp-api-user",
       "password": "secure-password"
     }'
   ```

2. **Set Permissions:**
   ```bash
   curl -u admin:admin -k -X POST \
     "https://wazuh:55000/security/roles/mcp-role/policies" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "mcp-policy",
       "policy": {
         "actions": ["cluster:read", "agents:read", "alerts:read"]
       }
     }'
   ```

## Monitoring

### Health Checks

```bash
# Basic health check
curl -k https://localhost:8443/health

# Detailed status
docker-compose exec wazuh-mcp-server python -c "
import psutil
print(f'CPU: {psutil.cpu_percent()}%')
print(f'Memory: {psutil.virtual_memory().percent}%')
"
```

### Log Monitoring

```bash
# View logs
docker-compose logs -f --tail=100

# Parse JSON logs
docker-compose logs | jq 'select(.level == "ERROR")'

# Log rotation (docker-compose.yml)
logging:
  driver: json-file
  options:
    max-size: "100m"
    max-file: "10"
```

## Performance Tuning

### Container Resources

```yaml
# docker-compose.yml
deploy:
  resources:
    limits:
      cpus: '4.0'
      memory: 2G
    reservations:
      cpus: '2.0'
      memory: 1G
```

### Application Tuning

```bash
# Increase worker processes for multi-core
WORKER_PROCESSES=8

# Adjust connection limits
MAX_CONNECTIONS=2000

# Enable connection pooling
CONNECTION_POOL_SIZE=50
```

## Backup and Recovery

### Backup Script

```bash
#!/bin/bash
# backup-mcp.sh
BACKUP_DIR="/backup/wazuh-mcp/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup configuration
docker cp wazuh-mcp-server:/app/config "$BACKUP_DIR/"

# Backup volumes
docker run --rm \
  -v wazuh-mcp-config:/source \
  -v "$BACKUP_DIR":/backup \
  alpine tar czf /backup/config-backup.tar.gz -C /source .
```

### Restore Process

```bash
# Stop service
docker-compose down

# Restore volumes
docker run --rm \
  -v wazuh-mcp-config:/target \
  -v "$BACKUP_DIR":/backup \
  alpine tar xzf /backup/config-backup.tar.gz -C /target

# Start service
docker-compose up -d
```

## High Availability

### Load Balancer Configuration

```nginx
upstream wazuh_mcp {
    server mcp1.internal:8443;
    server mcp2.internal:8443;
    server mcp3.internal:8443;
}

server {
    listen 443 ssl;
    server_name wazuh-mcp.internal;
    
    ssl_certificate /etc/nginx/ssl/cert.pem;
    ssl_certificate_key /etc/nginx/ssl/key.pem;
    
    location / {
        proxy_pass https://wazuh_mcp;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

## Maintenance

### Updates

```bash
# 1. Pull latest code
git pull origin main

# 2. Rebuild container
docker-compose build --no-cache

# 3. Rolling update
docker-compose up -d --no-deps --scale wazuh-mcp-server=2
docker-compose up -d --no-deps wazuh-mcp-server
```

### Health Monitoring

```bash
# Create monitoring script
cat > /usr/local/bin/check-mcp-health.sh << 'EOF'
#!/bin/bash
if ! curl -sf -k https://localhost:8443/health > /dev/null; then
    echo "MCP Server health check failed" | mail -s "MCP Alert" ops@company.com
    systemctl restart wazuh-mcp
fi
EOF

# Add to crontab
*/5 * * * * /usr/local/bin/check-mcp-health.sh
```

## Troubleshooting

### Common Issues

1. **Connection Refused**
   ```bash
   # Check if service is running
   docker ps | grep wazuh-mcp
   
   # Check logs
   docker-compose logs --tail=50
   ```

2. **Authentication Failures**
   ```bash
   # Verify API credentials
   curl -u user:pass https://wazuh:55000/security/user/authenticate
   
   # Check token expiration
   docker-compose logs | grep "JWT"
   ```

3. **Performance Issues**
   ```bash
   # Check resource usage
   docker stats wazuh-mcp-server
   
   # Increase resources if needed
   docker-compose up -d --scale wazuh-mcp-server=2
   ```

## Security Checklist

- [ ] Change default passwords
- [ ] Use strong JWT secret key
- [ ] Enable firewall rules
- [ ] Configure SSL certificates
- [ ] Set up log monitoring
- [ ] Enable audit logging
- [ ] Configure backup schedule
- [ ] Test disaster recovery
- [ ] Document procedures
- [ ] Train operations team