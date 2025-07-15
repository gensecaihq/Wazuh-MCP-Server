# Operational Runbooks - Wazuh MCP Server v3.0.0

## Overview

This document contains operational runbooks for common maintenance, troubleshooting, and emergency procedures for Wazuh MCP Server v3.0.0 production deployments.

## Table of Contents

1. [Deployment Procedures](#deployment-procedures)
2. [Monitoring and Health Checks](#monitoring-and-health-checks)
3. [Backup and Recovery](#backup-and-recovery)
4. [Security Operations](#security-operations)
5. [Performance Tuning](#performance-tuning)
6. [Troubleshooting](#troubleshooting)
7. [Maintenance](#maintenance)
8. [Emergency Procedures](#emergency-procedures)

---

## Deployment Procedures

### Standard Deployment

**Purpose**: Deploy Wazuh MCP Server in production environment

**Prerequisites**:
- Docker and Docker Compose installed
- SSL certificates prepared
- Environment variables configured
- Minimum 8GB RAM, 4 CPU cores, 50GB disk space

**Steps**:
1. **Prepare Environment**
   ```bash
   # Clone repository
   git clone https://github.com/wazuh-mcp-server/wazuh-mcp-server.git
   cd wazuh-mcp-server
   
   # Copy environment template
   cp .env.example .env
   
   # Edit environment variables
   nano .env
   ```

2. **Deploy Services**
   ```bash
   # Standard deployment
   docker-compose up -d
   
   # Verify deployment
   docker-compose ps
   docker-compose logs -f
   ```

3. **Verify Health**
   ```bash
   # Check service health
   curl -k https://localhost:8443/health
   
   # Check metrics
   curl http://localhost:9090/metrics
   ```

**Rollback Procedure**:
```bash
# Stop services
docker-compose down

# Restore from backup
./scripts/restore-backup.sh /path/to/backup

# Restart services
docker-compose up -d
```

### High Availability Deployment

**Purpose**: Deploy HA cluster with load balancing

**Prerequisites**:
- Multiple nodes (minimum 3)
- Shared storage for Redis
- Load balancer configuration

**Steps**:
1. **Deploy HA Stack**
   ```bash
   # Deploy HA configuration
   ./scripts/deploy-ha.sh deploy
   
   # Verify cluster status
   ./scripts/deploy-ha.sh status
   ```

2. **Configure Load Balancer**
   ```bash
   # Check HAProxy status
   curl http://localhost:8080/stats
   
   # Verify backend servers
   echo "show stat" | socat stdio /var/run/haproxy.sock
   ```

3. **Test Failover**
   ```bash
   # Simulate server failure
   docker-compose -f docker-compose.ha.yml stop wazuh-mcp-server-1
   
   # Verify automatic failover
   curl -k https://localhost:8443/health
   ```

---

## Monitoring and Health Checks

### Service Health Monitoring

**Purpose**: Monitor service health and performance

**Health Check Endpoints**:
- **Main Service**: `https://localhost:8443/health`
- **Metrics**: `http://localhost:9090/metrics`
- **Redis**: `redis-cli ping`
- **HAProxy**: `http://localhost:8080/stats`

**Health Check Script**:
```bash
#!/bin/bash
# health-check.sh

check_service() {
    local service=$1
    local url=$2
    local expected_status=$3
    
    status=$(curl -s -o /dev/null -w "%{http_code}" -k "$url")
    
    if [ "$status" -eq "$expected_status" ]; then
        echo "✅ $service: OK"
        return 0
    else
        echo "❌ $service: FAILED (HTTP $status)"
        return 1
    fi
}

# Check all services
check_service "MCP Server" "https://localhost:8443/health" 200
check_service "Prometheus" "http://localhost:9090/-/healthy" 200
check_service "Grafana" "http://localhost:3000/api/health" 200
check_service "HAProxy" "http://localhost:8080/stats" 200
```

### Performance Monitoring

**Purpose**: Monitor system performance and resource usage

**Key Metrics**:
- **Response Time**: < 200ms (95th percentile)
- **Throughput**: > 1000 requests/second
- **CPU Usage**: < 80%
- **Memory Usage**: < 80%
- **Disk Usage**: < 85%
- **Error Rate**: < 1%

**Prometheus Queries**:
```promql
# Response time
histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))

# Throughput
rate(http_requests_total[5m])

# Error rate
rate(http_requests_total{status=~"5.."}[5m]) / rate(http_requests_total[5m])

# CPU usage
100 - (avg(rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100)

# Memory usage
(node_memory_MemTotal_bytes - node_memory_MemAvailable_bytes) / node_memory_MemTotal_bytes * 100
```

---

## Backup and Recovery

### Database Backup

**Purpose**: Create backup of Redis data and configuration

**Backup Procedure**:
```bash
#!/bin/bash
# backup-redis.sh

BACKUP_DIR="/backup/redis/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Create Redis backup
docker-compose exec redis redis-cli BGSAVE

# Wait for backup to complete
while [ "$(docker-compose exec redis redis-cli LASTSAVE)" -eq "$last_save" ]; do
    sleep 1
done

# Copy backup file
docker cp $(docker-compose ps -q redis):/data/dump.rdb "$BACKUP_DIR/"

# Backup configuration
cp config/redis.conf "$BACKUP_DIR/"

echo "Backup completed: $BACKUP_DIR"
```

**Restore Procedure**:
```bash
#!/bin/bash
# restore-redis.sh

BACKUP_PATH=$1

if [ -z "$BACKUP_PATH" ]; then
    echo "Usage: $0 /path/to/backup/directory"
    exit 1
fi

# Stop Redis
docker-compose stop redis

# Restore backup
docker cp "$BACKUP_PATH/dump.rdb" $(docker-compose ps -q redis):/data/

# Restore configuration
cp "$BACKUP_PATH/redis.conf" config/

# Start Redis
docker-compose start redis

echo "Restore completed from: $BACKUP_PATH"
```

### Configuration Backup

**Purpose**: Backup system configuration and certificates

**Backup Script**:
```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR="/backup/config/$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BACKUP_DIR"

# Backup configuration files
cp -r config/ "$BACKUP_DIR/"
cp -r certs/ "$BACKUP_DIR/"
cp .env "$BACKUP_DIR/"
cp docker-compose*.yml "$BACKUP_DIR/"

# Create tarball
tar -czf "$BACKUP_DIR.tar.gz" -C "$BACKUP_DIR" .

echo "Configuration backup completed: $BACKUP_DIR.tar.gz"
```

---

## Security Operations

### Certificate Management

**Purpose**: Manage SSL/TLS certificates

**Certificate Renewal**:
```bash
#!/bin/bash
# renew-certificates.sh

# Backup existing certificates
cp -r certs/ certs.backup.$(date +%Y%m%d)

# Generate new certificates
openssl genrsa -out certs/wazuh-mcp.key 2048
openssl req -new -key certs/wazuh-mcp.key -out certs/wazuh-mcp.csr \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=your-domain.com"

# Sign certificate (replace with your CA process)
openssl x509 -req -days 365 -in certs/wazuh-mcp.csr \
    -signkey certs/wazuh-mcp.key -out certs/wazuh-mcp.crt

# Combine for HAProxy
cat certs/wazuh-mcp.crt certs/wazuh-mcp.key > certs/wazuh-mcp.pem

# Reload services
docker-compose restart load-balancer
```

### Security Audit

**Purpose**: Perform security audit and compliance check

**Audit Script**:
```bash
#!/bin/bash
# security-audit.sh

echo "=== Security Audit Report ==="
echo "Date: $(date)"
echo "Host: $(hostname)"
echo

# Check certificate expiration
echo "1. Certificate Status:"
openssl x509 -in certs/wazuh-mcp.crt -noout -dates

# Check for weak passwords
echo "2. Password Policy Check:"
# This would integrate with your password policy validation

# Check file permissions
echo "3. File Permissions:"
find . -name "*.key" -exec ls -la {} \;
find . -name "*.pem" -exec ls -la {} \;

# Check for exposed secrets
echo "4. Secret Exposure Check:"
grep -r "password\|secret\|key" --include="*.yml" --include="*.yaml" . | grep -v "example"

# Check container security
echo "5. Container Security:"
docker-compose ps --format "table {{.Name}}\t{{.State}}\t{{.Ports}}"

# Check network security
echo "6. Network Configuration:"
docker network ls
docker network inspect wazuh-mcp-network

echo "=== Audit Complete ==="
```

### User Management

**Purpose**: Manage user accounts and permissions

**Create User**:
```bash
#!/bin/bash
# create-user.sh

USERNAME=$1
EMAIL=$2
ROLE=${3:-user}

if [ -z "$USERNAME" ] || [ -z "$EMAIL" ]; then
    echo "Usage: $0 <username> <email> [role]"
    exit 1
fi

# Use API to create user
curl -X POST -k "https://localhost:8443/api/admin/users" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d "{
        \"username\": \"$USERNAME\",
        \"email\": \"$EMAIL\",
        \"role\": \"$ROLE\",
        \"password_change_required\": true
    }"
```

**Revoke User Access**:
```bash
#!/bin/bash
# revoke-user.sh

USERNAME=$1

if [ -z "$USERNAME" ]; then
    echo "Usage: $0 <username>"
    exit 1
fi

# Revoke all tokens for user
curl -X DELETE -k "https://localhost:8443/api/admin/users/$USERNAME/tokens" \
    -H "Authorization: Bearer $ADMIN_TOKEN"

# Disable user account
curl -X PATCH -k "https://localhost:8443/api/admin/users/$USERNAME" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d "{\"is_active\": false}"
```

---

## Performance Tuning

### Database Optimization

**Purpose**: Optimize Redis performance

**Redis Configuration**:
```bash
# redis-optimize.sh

# Memory optimization
echo "maxmemory 2gb" >> config/redis.conf
echo "maxmemory-policy allkeys-lru" >> config/redis.conf

# Persistence optimization
echo "save 900 1" >> config/redis.conf
echo "save 300 10" >> config/redis.conf
echo "save 60 10000" >> config/redis.conf

# Network optimization
echo "tcp-keepalive 300" >> config/redis.conf
echo "timeout 0" >> config/redis.conf

# Restart Redis
docker-compose restart redis
```

### Load Balancer Tuning

**Purpose**: Optimize HAProxy performance

**HAProxy Tuning**:
```bash
# Add to haproxy.cfg
global
    maxconn 4096
    nbthread 4
    
defaults
    timeout connect 5000ms
    timeout client 50000ms
    timeout server 50000ms
    
backend wazuh_mcp_servers
    balance roundrobin
    option httpchk GET /health
    http-reuse safe
```

### Application Performance

**Purpose**: Optimize application performance

**Performance Monitoring**:
```bash
#!/bin/bash
# performance-monitor.sh

echo "=== Performance Report ==="
echo "Date: $(date)"
echo

# Response time
echo "Response Time (last 5 minutes):"
curl -s "http://localhost:9090/api/v1/query?query=histogram_quantile(0.95,%20rate(http_request_duration_seconds_bucket[5m]))"

# Throughput
echo "Throughput (requests/second):"
curl -s "http://localhost:9090/api/v1/query?query=rate(http_requests_total[5m])"

# Error rate
echo "Error Rate:"
curl -s "http://localhost:9090/api/v1/query?query=rate(http_requests_total{status=~\"5..\"}[5m])"

# Resource usage
echo "CPU Usage:"
top -bn1 | grep "Cpu(s)" | awk '{print $2}' | sed 's/%us,//'

echo "Memory Usage:"
free -h | grep "Mem:" | awk '{print $3 "/" $2}'

echo "Disk Usage:"
df -h | grep "/$" | awk '{print $3 "/" $2 " (" $5 ")"}'
```

---

## Troubleshooting

### Common Issues

#### Service Won't Start

**Symptoms**: Docker containers fail to start
**Diagnosis**:
```bash
# Check container logs
docker-compose logs wazuh-mcp-server

# Check resource usage
docker stats

# Check disk space
df -h

# Check memory
free -h
```

**Solutions**:
1. **Insufficient Resources**: Increase memory/CPU allocation
2. **Port Conflicts**: Change port mappings in docker-compose.yml
3. **Permission Issues**: Fix file permissions
4. **Configuration Errors**: Validate configuration files

#### High Response Times

**Symptoms**: API responses > 1 second
**Diagnosis**:
```bash
# Check system load
uptime

# Check database performance
redis-cli --latency

# Check network latency
ping wazuh-server

# Check application logs
docker-compose logs -f wazuh-mcp-server
```

**Solutions**:
1. **Database Optimization**: Tune Redis configuration
2. **Connection Pooling**: Increase connection pool size
3. **Caching**: Implement additional caching layers
4. **Load Balancing**: Add more server instances

#### Authentication Failures

**Symptoms**: Users cannot authenticate
**Diagnosis**:
```bash
# Check authentication logs
grep "authentication" logs/security_audit.log

# Check JWT configuration
echo $JWT_SECRET_KEY | wc -c

# Check Redis connectivity
redis-cli ping

# Check certificate validity
openssl x509 -in certs/wazuh-mcp.crt -noout -dates
```

**Solutions**:
1. **JWT Secret**: Regenerate JWT secret key
2. **Redis Issues**: Restart Redis service
3. **Certificate Expiry**: Renew SSL certificates
4. **Account Lockout**: Unlock user accounts

### Log Analysis

**Purpose**: Analyze logs for troubleshooting

**Log Locations**:
- Application logs: `logs/wazuh-mcp.log`
- Security audit: `logs/security_audit.log`
- Access logs: `logs/access.log`
- Error logs: `logs/error.log`

**Log Analysis Commands**:
```bash
# Find errors in last hour
grep "ERROR\|CRITICAL" logs/wazuh-mcp.log | grep "$(date -d '1 hour ago' '+%Y-%m-%d %H')"

# Authentication failures
grep "authentication_failure" logs/security_audit.log | tail -20

# Top IP addresses
awk '{print $1}' logs/access.log | sort | uniq -c | sort -nr | head -10

# Response time analysis
awk '{print $10}' logs/access.log | sort -n | tail -20
```

---

## Maintenance

### Regular Maintenance Tasks

#### Daily Tasks

**Log Rotation**:
```bash
#!/bin/bash
# rotate-logs.sh

LOG_DIR="logs"
RETENTION_DAYS=30

# Compress old logs
find "$LOG_DIR" -name "*.log" -mtime +1 -exec gzip {} \;

# Remove old compressed logs
find "$LOG_DIR" -name "*.gz" -mtime +$RETENTION_DAYS -delete

# Restart services to create new log files
docker-compose restart wazuh-mcp-server
```

**Health Check**:
```bash
#!/bin/bash
# daily-health-check.sh

# Run health checks
./scripts/health-check.sh

# Check disk space
df -h | awk '$5 > 80 {print "WARNING: " $0}'

# Check memory usage
free -h | awk '/Mem:/ {if ($3/$2 > 0.8) print "WARNING: High memory usage"}'

# Check certificate expiry
openssl x509 -in certs/wazuh-mcp.crt -noout -checkend 604800 || echo "WARNING: Certificate expires within 7 days"
```

#### Weekly Tasks

**Database Maintenance**:
```bash
#!/bin/bash
# weekly-maintenance.sh

# Create database backup
./scripts/backup-redis.sh

# Optimize database
redis-cli BGREWRITEAOF

# Clean up expired tokens
redis-cli --scan --pattern "blacklist:*" | xargs -r redis-cli DEL

# Update security signatures
./scripts/update-security-rules.sh
```

#### Monthly Tasks

**Security Review**:
```bash
#!/bin/bash
# monthly-security-review.sh

# Run security audit
./scripts/security-audit.sh > reports/security-audit-$(date +%Y%m).txt

# Review user accounts
./scripts/review-user-accounts.sh

# Update dependencies
docker-compose pull
docker-compose up -d

# Certificate renewal check
./scripts/check-certificate-expiry.sh
```

### Scheduled Maintenance

**Purpose**: Perform scheduled maintenance with minimal downtime

**Maintenance Window Procedure**:
```bash
#!/bin/bash
# maintenance-window.sh

# 1. Announce maintenance
echo "Maintenance starting at $(date)" | tee -a logs/maintenance.log

# 2. Enable maintenance mode
curl -X POST -k "https://localhost:8443/api/admin/maintenance" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d '{"enabled": true}'

# 3. Wait for active connections to finish
sleep 30

# 4. Perform maintenance tasks
./scripts/backup-redis.sh
./scripts/update-certificates.sh
./scripts/optimize-database.sh

# 5. Restart services
docker-compose restart

# 6. Verify health
./scripts/health-check.sh

# 7. Disable maintenance mode
curl -X POST -k "https://localhost:8443/api/admin/maintenance" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -d '{"enabled": false}'

# 8. Confirm maintenance completion
echo "Maintenance completed at $(date)" | tee -a logs/maintenance.log
```

---

## Emergency Procedures

### Service Recovery

**Purpose**: Quickly restore service after failure

**Emergency Recovery Steps**:
1. **Assess Impact**
   ```bash
   # Check service status
   docker-compose ps
   
   # Check logs for errors
   docker-compose logs --tail=50
   
   # Check resource usage
   docker stats
   ```

2. **Immediate Actions**
   ```bash
   # Stop all services
   docker-compose down
   
   # Clean up containers
   docker system prune -f
   
   # Restart services
   docker-compose up -d
   ```

3. **Verify Recovery**
   ```bash
   # Check health
   ./scripts/health-check.sh
   
   # Monitor logs
   docker-compose logs -f
   ```

### Data Recovery

**Purpose**: Recover from data corruption or loss

**Recovery Procedure**:
```bash
#!/bin/bash
# emergency-data-recovery.sh

BACKUP_PATH=$1

if [ -z "$BACKUP_PATH" ]; then
    echo "Usage: $0 /path/to/backup"
    exit 1
fi

# Stop all services
docker-compose down

# Clear corrupted data
rm -rf data/redis/*

# Restore from backup
tar -xzf "$BACKUP_PATH" -C .

# Restore database
docker-compose up -d redis
sleep 10

# Restore application data
docker cp "$BACKUP_PATH/dump.rdb" $(docker-compose ps -q redis):/data/

# Restart all services
docker-compose up -d

# Verify recovery
./scripts/health-check.sh
```

### Security Incident Response

**Purpose**: Respond to security incidents

**Incident Response Steps**:
1. **Isolate Affected Systems**
   ```bash
   # Block suspicious IPs
   iptables -A INPUT -s $SUSPICIOUS_IP -j DROP
   
   # Revoke all tokens
   redis-cli FLUSHDB
   
   # Enable security mode
   curl -X POST -k "https://localhost:8443/api/admin/security-mode" \
       -H "Authorization: Bearer $ADMIN_TOKEN" \
       -d '{"enabled": true}'
   ```

2. **Collect Evidence**
   ```bash
   # Capture logs
   cp logs/* /evidence/logs/
   
   # Capture system state
   docker-compose ps > /evidence/container-state.txt
   ps aux > /evidence/process-state.txt
   netstat -an > /evidence/network-state.txt
   ```

3. **Notify Stakeholders**
   ```bash
   # Send alert notification
   ./scripts/send-security-alert.sh "Security incident detected"
   
   # Update status page
   curl -X POST "https://status.company.com/api/incidents" \
       -H "Authorization: Bearer $STATUS_TOKEN" \
       -d '{"message": "Security incident under investigation"}'
   ```

### Contact Information

**Emergency Contacts**:
- **Incident Commander**: +1-555-0101
- **Security Team**: +1-555-0102
- **Technical Lead**: +1-555-0103
- **Management**: +1-555-0104

**External Contacts**:
- **Cloud Provider**: +1-206-266-4064
- **Security Vendor**: +1-888-512-8906
- **Legal Counsel**: +1-555-0200

---

## Conclusion

These runbooks provide standardized procedures for operating Wazuh MCP Server v3.0.0 in production environments. Regular practice and updates ensure effective incident response and system maintenance.

**Important Notes**:
- Test all procedures in a non-production environment first
- Keep runbooks updated with system changes
- Train all team members on emergency procedures
- Document all incidents and lessons learned
- Regular review and improvement of procedures

For additional support, consult the official documentation or contact the support team.