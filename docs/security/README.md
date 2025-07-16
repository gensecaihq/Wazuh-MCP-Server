# Security Guide - Wazuh MCP Server v3.0.0

## Overview

This guide provides comprehensive security configuration and best practices for deploying Wazuh MCP Server v3.0.0 in production environments.

## Table of Contents

1. [Authentication and Authorization](#authentication-and-authorization)
2. [Network Security](#network-security)
3. [Data Protection](#data-protection)
4. [Container Security](#container-security)
5. [Monitoring and Auditing](#monitoring-and-auditing)
6. [Incident Response](#incident-response)
7. [Compliance](#compliance)
8. [Security Hardening](#security-hardening)

## Authentication and Authorization

### OAuth 2.0 Configuration

#### Basic OAuth2 Setup

```bash
# Generate secure secrets
export JWT_SECRET_KEY=$(openssl rand -base64 32)
export OAUTH_CLIENT_SECRET=$(openssl rand -base64 32)

# Configure OAuth2 in .env
cat >> .env << EOF
# OAuth2 Configuration
OAUTH_ENABLED=true
JWT_SECRET_KEY=${JWT_SECRET_KEY}
OAUTH_CLIENT_ID=wazuh-mcp-client
OAUTH_CLIENT_SECRET=${OAUTH_CLIENT_SECRET}
OAUTH_TOKEN_EXPIRY=3600
OAUTH_REFRESH_TOKEN_EXPIRY=86400
EOF
```

#### Advanced OAuth2 Configuration

```env
# OAuth2 Advanced Settings
OAUTH_AUTHORIZATION_CODE_EXPIRY=600
OAUTH_REQUIRE_HTTPS=true
OAUTH_ENFORCE_PKCE=true
OAUTH_ALLOW_INSECURE_HTTP=false

# JWT Configuration
JWT_ALGORITHM=HS256
JWT_ACCESS_TOKEN_EXPIRY=3600
JWT_REFRESH_TOKEN_EXPIRY=86400
JWT_KEY_ROTATION_INTERVAL=2592000  # 30 days

# Scopes Configuration
OAUTH_DEFAULT_SCOPES=read:alerts,read:agents
OAUTH_ADMIN_SCOPES=admin:*
OAUTH_READONLY_SCOPES=read:*
```

#### Client Management

```python
# Create OAuth2 client
from wazuh_mcp_server.auth.oauth2 import OAuth2Manager

oauth = OAuth2Manager()

# Create client for web application
web_client = oauth.create_client(
    client_id='wazuh-mcp-web',
    client_secret='secure-web-client-secret',
    client_type='confidential',
    redirect_uris=['https://webapp.example.com/callback'],
    scopes=['read:alerts', 'read:agents', 'read:vulnerabilities'],
    grant_types=['authorization_code', 'refresh_token']
)

# Create client for mobile application
mobile_client = oauth.create_client(
    client_id='wazuh-mcp-mobile',
    client_type='public',
    redirect_uris=['wazuh-mcp://callback'],
    scopes=['read:alerts', 'read:agents'],
    grant_types=['authorization_code'],
    require_pkce=True
)
```

### User Management

#### User Creation and Roles

```python
from wazuh_mcp_server.auth.models import User, Role

# Create admin user
admin_user = User.create_user(
    username='admin',
    password='SecurePassword123!',
    email='admin@example.com',
    scopes=['admin:*'],
    require_password_change=True
)

# Create security analyst user
analyst_user = User.create_user(
    username='analyst',
    password='AnalystPassword123!',
    email='analyst@example.com',
    scopes=['read:alerts', 'read:agents', 'read:vulnerabilities'],
    require_password_change=True
)

# Create read-only user
readonly_user = User.create_user(
    username='readonly',
    password='ReadOnlyPassword123!',
    email='readonly@example.com',
    scopes=['read:alerts'],
    require_password_change=True
)
```

#### Password Policy

```env
# Password Policy Configuration
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SYMBOLS=true
PASSWORD_MAX_AGE=90
PASSWORD_HISTORY_COUNT=5
PASSWORD_LOCKOUT_ATTEMPTS=5
PASSWORD_LOCKOUT_DURATION=1800
```

### Multi-Factor Authentication (MFA)

```python
from wazuh_mcp_server.auth.mfa import TOTPManager

# Enable MFA for user
totp_manager = TOTPManager()
secret = totp_manager.generate_secret()
qr_code = totp_manager.generate_qr_code(secret, 'admin@example.com')

# Verify MFA token
is_valid = totp_manager.verify_token(secret, user_token)
```

## Network Security

### SSL/TLS Configuration

#### Certificate Management

```bash
# Generate production certificates
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=wazuh-mcp-server.example.com"

# Set proper permissions
chmod 600 server.key
chmod 644 server.crt

# Configure certificate paths
cat >> .env << EOF
SSL_CERT_PATH=/certs/server.crt
SSL_KEY_PATH=/certs/server.key
SSL_CA_PATH=/certs/ca.crt
SSL_VERIFY_MODE=required
EOF
```

#### TLS Configuration

```env
# TLS Security Settings
TLS_MIN_VERSION=1.2
TLS_MAX_VERSION=1.3
TLS_CIPHER_SUITES=ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256
TLS_PREFER_SERVER_CIPHERS=true
TLS_SESSION_TIMEOUT=300
TLS_HSTS_MAX_AGE=31536000
TLS_HSTS_INCLUDE_SUBDOMAINS=true
```

### Firewall Configuration

#### IPTables Rules

```bash
#!/bin/bash
# firewall-rules.sh

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (restrict to specific IPs)
iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 22 -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow MCP server
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT

# Allow monitoring (internal only)
iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 9090 -j ACCEPT
iptables -A INPUT -p tcp -s 10.0.0.0/8 --dport 3000 -j ACCEPT

# Rate limiting
iptables -A INPUT -p tcp --dport 8443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# Drop everything else
iptables -A INPUT -j DROP
```

#### UFW Configuration

```bash
# Reset UFW
sudo ufw --force reset

# Default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (from specific subnet)
sudo ufw allow from 10.0.0.0/8 to any port 22

# Allow HTTP/HTTPS
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow MCP server
sudo ufw allow 8443/tcp

# Allow monitoring (internal only)
sudo ufw allow from 10.0.0.0/8 to any port 9090
sudo ufw allow from 10.0.0.0/8 to any port 3000

# Rate limiting
sudo ufw limit 8443/tcp

# Enable firewall
sudo ufw enable
```

### Network Segmentation

#### VLAN Configuration

```bash
# Create security services VLAN
sudo vconfig add eth0 100
sudo ifconfig eth0.100 10.100.1.1 netmask 255.255.255.0 up

# Configure routing
sudo ip route add 10.100.1.0/24 dev eth0.100
```

#### Docker Network Security

```yaml
# docker compose.yml
networks:
  frontend:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16
  backend:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.21.0.0/16
  monitoring:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.22.0.0/16

services:
  wazuh-mcp-server:
    networks:
      - frontend
      - backend
  
  redis:
    networks:
      - backend
  
  prometheus:
    networks:
      - backend
      - monitoring
```

## Data Protection

### Data Encryption

#### At-Rest Encryption

```bash
# Enable disk encryption
sudo cryptsetup luksFormat /dev/sdb
sudo cryptsetup luksOpen /dev/sdb wazuh-mcp-data
sudo mkfs.ext4 /dev/mapper/wazuh-mcp-data
sudo mount /dev/mapper/wazuh-mcp-data /opt/wazuh-mcp-server/data

# Configure automatic mounting
echo "/dev/mapper/wazuh-mcp-data /opt/wazuh-mcp-server/data ext4 defaults 0 2" >> /etc/fstab
```

#### Database Encryption

```env
# Redis encryption
REDIS_ENCRYPTION_ENABLED=true
REDIS_ENCRYPTION_KEY=your-32-byte-encryption-key

# JWT encryption
JWT_ENCRYPTION_ENABLED=true
JWT_ENCRYPTION_KEY=your-32-byte-encryption-key
```

### Data Backup Security

```bash
#!/bin/bash
# secure-backup.sh

set -euo pipefail

BACKUP_DIR="/opt/backups/wazuh-mcp-server"
ENCRYPTION_KEY="/etc/wazuh-mcp-server/backup.key"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create encrypted backup
tar -czf - /opt/wazuh-mcp-server/data | \
  openssl enc -aes-256-cbc -pbkdf2 -kfile "$ENCRYPTION_KEY" > \
  "$BACKUP_DIR/wazuh-mcp-backup-$TIMESTAMP.tar.gz.enc"

# Upload to secure storage
aws s3 cp "$BACKUP_DIR/wazuh-mcp-backup-$TIMESTAMP.tar.gz.enc" \
  "s3://wazuh-mcp-backups/encrypted/" \
  --sse AES256
```

### Data Retention and Disposal

```env
# Data retention policies
DATA_RETENTION_DAYS=90
LOG_RETENTION_DAYS=365
AUDIT_LOG_RETENTION_DAYS=2555  # 7 years
BACKUP_RETENTION_DAYS=90

# Secure deletion
SECURE_DELETE_ENABLED=true
SECURE_DELETE_PASSES=3
```

## Container Security

### Docker Security Configuration

#### Dockerfile Security

```dockerfile
# Use specific version tags
FROM python:3.9.18-slim

# Create non-root user
RUN groupadd -r wazuh-mcp && useradd -r -g wazuh-mcp wazuh-mcp

# Install dependencies as root
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=wazuh-mcp:wazuh-mcp src/ /app/

# Set working directory
WORKDIR /app

# Drop privileges
USER wazuh-mcp

# Use read-only filesystem
RUN mkdir -p /tmp /var/tmp
VOLUME ["/tmp", "/var/tmp"]

# Security settings
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8443/health || exit 1

# Expose port
EXPOSE 8443

# Run application
CMD ["python", "-m", "wazuh_mcp_server.remote_server"]
```

#### Docker Compose Security

```yaml
version: '3.8'

services:
  wazuh-mcp-server:
    build: .
    read_only: true
    tmpfs:
      - /tmp
      - /var/tmp
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    security_opt:
      - no-new-privileges:true
      - apparmor:docker-default
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '0.5'
        reservations:
          memory: 512M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8443/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Container Runtime Security

#### AppArmor Profile

```bash
# Create AppArmor profile
cat > /etc/apparmor.d/docker-wazuh-mcp << 'EOF'
#include <tunables/global>

profile docker-wazuh-mcp flags=(attach_disconnected,mediate_deleted) {
  #include <abstractions/base>
  
  # Allow network access
  network inet tcp,
  network inet udp,
  
  # Allow file system access
  /app/** r,
  /tmp/** rw,
  /var/tmp/** rw,
  
  # Deny dangerous capabilities
  deny capability sys_admin,
  deny capability sys_module,
  deny capability sys_rawio,
  
  # Allow required capabilities
  capability net_bind_service,
}
EOF

# Load profile
sudo apparmor_parser -r /etc/apparmor.d/docker-wazuh-mcp
```

#### Seccomp Profile

```json
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "archMap": [
    {
      "architecture": "SCMP_ARCH_X86_64",
      "subArchitectures": [
        "SCMP_ARCH_X86",
        "SCMP_ARCH_X32"
      ]
    }
  ],
  "syscalls": [
    {
      "names": [
        "accept",
        "accept4",
        "access",
        "bind",
        "brk",
        "close",
        "connect",
        "dup",
        "dup2",
        "epoll_create",
        "epoll_create1",
        "epoll_ctl",
        "epoll_wait",
        "exit",
        "exit_group",
        "fcntl",
        "fstat",
        "futex",
        "getdents",
        "getdents64",
        "getpid",
        "getppid",
        "getsockname",
        "getsockopt",
        "listen",
        "lseek",
        "mmap",
        "munmap",
        "open",
        "openat",
        "read",
        "readv",
        "recv",
        "recvfrom",
        "rt_sigaction",
        "rt_sigprocmask",
        "rt_sigreturn",
        "send",
        "sendto",
        "setsockopt",
        "socket",
        "stat",
        "write",
        "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

## Monitoring and Auditing

### Security Event Logging

#### Audit Log Configuration

```env
# Audit logging configuration
ENABLE_AUDIT_LOG=true
AUDIT_LOG_LEVEL=INFO
AUDIT_LOG_FORMAT=json
AUDIT_LOG_FILE=/var/log/wazuh-mcp-server/audit.log
AUDIT_LOG_MAX_SIZE=100MB
AUDIT_LOG_BACKUP_COUNT=10

# Security events to log
AUDIT_LOG_AUTHENTICATION=true
AUDIT_LOG_AUTHORIZATION=true
AUDIT_LOG_API_CALLS=true
AUDIT_LOG_CONFIGURATION_CHANGES=true
AUDIT_LOG_SYSTEM_EVENTS=true
```

#### Security Monitoring

```python
from wazuh_mcp_server.utils.security_audit import SecurityAuditor

# Initialize security auditor
auditor = SecurityAuditor()

# Log authentication events
auditor.log_authentication_event(
    user_id='admin',
    event_type='login_success',
    ip_address='192.168.1.100',
    user_agent='Mozilla/5.0...'
)

# Log authorization events
auditor.log_authorization_event(
    user_id='analyst',
    resource='/api/alerts',
    action='read',
    result='allowed'
)

# Log suspicious activity
auditor.log_security_violation(
    event_type='brute_force_attempt',
    ip_address='192.168.1.200',
    details={'attempts': 10, 'timeframe': '5m'}
)
```

### Real-time Security Monitoring

#### Prometheus Security Metrics

```python
# Security metrics
from prometheus_client import Counter, Histogram, Gauge

# Authentication metrics
auth_attempts_total = Counter('auth_attempts_total', 'Total authentication attempts', ['result'])
auth_failures_total = Counter('auth_failures_total', 'Total authentication failures', ['reason'])

# Authorization metrics
authz_requests_total = Counter('authz_requests_total', 'Total authorization requests', ['resource', 'action'])
authz_denied_total = Counter('authz_denied_total', 'Total authorization denials', ['resource', 'reason'])

# Security events
security_violations_total = Counter('security_violations_total', 'Total security violations', ['type'])
suspicious_activity_total = Counter('suspicious_activity_total', 'Total suspicious activities', ['type'])
```

#### Alerting Rules

```yaml
# prometheus-security-rules.yml
groups:
  - name: security-alerts
    rules:
      - alert: BruteForceAttack
        expr: rate(auth_failures_total[5m]) > 5
        for: 2m
        labels:
          severity: high
        annotations:
          summary: "Brute force attack detected"
          description: "High authentication failure rate: {{ $value }} failures/sec"
      
      - alert: SecurityViolation
        expr: increase(security_violations_total[5m]) > 0
        for: 0s
        labels:
          severity: critical
        annotations:
          summary: "Security violation detected"
          description: "Security violation of type {{ $labels.type }}"
      
      - alert: SuspiciousActivity
        expr: increase(suspicious_activity_total[15m]) > 10
        for: 5m
        labels:
          severity: medium
        annotations:
          summary: "Suspicious activity detected"
          description: "Elevated suspicious activity: {{ $value }} events in 15m"
```

## Incident Response

### Automated Response

#### Rate Limiting and IP Blocking

```python
from wazuh_mcp_server.utils.rate_limiter import RateLimiter
from wazuh_mcp_server.utils.ip_blocker import IPBlocker

# Rate limiting configuration
rate_limiter = RateLimiter(
    requests_per_minute=60,
    burst_size=10,
    window_size=60
)

# IP blocking for suspicious activity
ip_blocker = IPBlocker()

# Block IP for brute force attempts
def handle_brute_force(ip_address, attempts):
    if attempts > 10:
        ip_blocker.block_ip(ip_address, duration=3600)  # 1 hour
        auditor.log_security_event(
            event_type='ip_blocked',
            ip_address=ip_address,
            reason='brute_force_attempt'
        )
```

#### Incident Response Automation

```bash
#!/bin/bash
# incident-response.sh

set -euo pipefail

INCIDENT_TYPE="$1"
SEVERITY="$2"
DETAILS="$3"

case $INCIDENT_TYPE in
    "brute_force")
        # Block attacker IP
        IP=$(echo "$DETAILS" | jq -r '.ip_address')
        iptables -A INPUT -s "$IP" -j DROP
        
        # Send alert
        curl -X POST "$SLACK_WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"text\": \"🚨 Brute force attack blocked from $IP\"}"
        ;;
    
    "security_violation")
        # Disable user account
        USER=$(echo "$DETAILS" | jq -r '.user_id')
        python3 -c "
        from wazuh_mcp_server.auth.models import User
        user = User.get_by_username('$USER')
        user.disable_account()
        "
        
        # Send critical alert
        curl -X POST "$PAGERDUTY_API_URL" \
            -H "Authorization: Token token=$PAGERDUTY_API_KEY" \
            -H "Content-Type: application/json" \
            -d "{\"routing_key\": \"$PAGERDUTY_ROUTING_KEY\", \"event_action\": \"trigger\", \"payload\": {\"summary\": \"Security violation by user $USER\", \"severity\": \"critical\"}}"
        ;;
esac
```

### Manual Response Procedures

#### Security Incident Checklist

1. **Immediate Response**
   - [ ] Isolate affected systems
   - [ ] Preserve evidence
   - [ ] Document timeline
   - [ ] Notify stakeholders

2. **Investigation**
   - [ ] Analyze logs
   - [ ] Identify attack vector
   - [ ] Assess impact
   - [ ] Determine root cause

3. **Containment**
   - [ ] Block malicious IPs
   - [ ] Disable compromised accounts
   - [ ] Apply security patches
   - [ ] Update firewall rules

4. **Recovery**
   - [ ] Restore from backups
   - [ ] Rebuild compromised systems
   - [ ] Update security controls
   - [ ] Verify system integrity

5. **Post-Incident**
   - [ ] Conduct lessons learned
   - [ ] Update procedures
   - [ ] Improve monitoring
   - [ ] Report to authorities

## Compliance

### Security Frameworks

#### SOC 2 Type II Compliance

```env
# SOC 2 compliance settings
SOC2_COMPLIANCE_ENABLED=true
SOC2_AUDIT_TRAIL_ENABLED=true
SOC2_DATA_CLASSIFICATION_ENABLED=true
SOC2_ACCESS_CONTROL_ENABLED=true
SOC2_AVAILABILITY_MONITORING_ENABLED=true
SOC2_CONFIDENTIALITY_CONTROLS_ENABLED=true
SOC2_PROCESSING_INTEGRITY_ENABLED=true
SOC2_PRIVACY_CONTROLS_ENABLED=true
```

#### ISO 27001 Compliance

```env
# ISO 27001 compliance settings
ISO27001_COMPLIANCE_ENABLED=true
ISO27001_RISK_ASSESSMENT_ENABLED=true
ISO27001_SECURITY_POLICY_ENFORCED=true
ISO27001_INCIDENT_MANAGEMENT_ENABLED=true
ISO27001_BUSINESS_CONTINUITY_ENABLED=true
ISO27001_SUPPLIER_SECURITY_ENABLED=true
```

### Regulatory Compliance

#### GDPR Compliance

```python
from wazuh_mcp_server.utils.gdpr import GDPRManager

gdpr_manager = GDPRManager()

# Data subject rights
def handle_data_subject_request(request_type, user_id):
    if request_type == 'access':
        return gdpr_manager.export_user_data(user_id)
    elif request_type == 'deletion':
        return gdpr_manager.delete_user_data(user_id)
    elif request_type == 'portability':
        return gdpr_manager.export_portable_data(user_id)
```

#### HIPAA Compliance

```env
# HIPAA compliance settings
HIPAA_COMPLIANCE_ENABLED=true
HIPAA_AUDIT_CONTROLS_ENABLED=true
HIPAA_PERSON_AUTHENTICATION_ENABLED=true
HIPAA_TRANSMISSION_SECURITY_ENABLED=true
HIPAA_ACCESS_CONTROL_ENABLED=true
HIPAA_INTEGRITY_CONTROLS_ENABLED=true
```

## Security Hardening

### System Hardening

#### Operating System Security

```bash
#!/bin/bash
# system-hardening.sh

set -euo pipefail

# Update system
apt-get update && apt-get upgrade -y

# Install security tools
apt-get install -y fail2ban rkhunter chkrootkit

# Configure fail2ban
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log

[wazuh-mcp-server]
enabled = true
port = 8443
filter = wazuh-mcp-server
logpath = /var/log/wazuh-mcp-server/application.log
maxretry = 3
EOF

# Configure kernel parameters
cat >> /etc/sysctl.conf << 'EOF'
# Network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1

# Memory protection
kernel.randomize_va_space = 2
kernel.exec-shield = 1
kernel.dmesg_restrict = 1
kernel.kptr_restrict = 1
EOF

sysctl -p
```

#### Application Security

```env
# Application security settings
SECURITY_HEADERS_ENABLED=true
CSRF_PROTECTION_ENABLED=true
XSS_PROTECTION_ENABLED=true
CONTENT_TYPE_NOSNIFF_ENABLED=true
FRAME_OPTIONS_ENABLED=true
HSTS_ENABLED=true
REFERRER_POLICY_ENABLED=true
FEATURE_POLICY_ENABLED=true
```

### Database Security

#### Redis Security

```bash
# Redis security configuration
cat > /etc/redis/redis.conf << 'EOF'
# Network security
bind 127.0.0.1
port 6379
protected-mode yes

# Authentication
requirepass your-strong-redis-password
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command DEBUG ""
rename-command CONFIG "CONFIG_a4b6c8d2e5f7"

# Logging
logfile /var/log/redis/redis-server.log
syslog-enabled yes
syslog-ident redis

# Security
maxmemory 256mb
maxmemory-policy allkeys-lru
save 900 1
save 300 10
save 60 10000
EOF
```

### Regular Security Maintenance

#### Security Update Script

```bash
#!/bin/bash
# security-updates.sh

set -euo pipefail

echo "Starting security updates..."

# System updates
apt-get update
apt-get upgrade -y

# Docker updates
docker system prune -f
docker compose pull

# Application updates
cd /opt/wazuh-mcp-server
git pull origin main
pip install -r requirements.txt --upgrade

# Security scan
python3 scripts/security-scan.sh

# Restart services
systemctl restart wazuh-mcp-server
docker compose restart

echo "Security updates completed"
```

#### Vulnerability Assessment

```bash
#!/bin/bash
# vulnerability-assessment.sh

set -euo pipefail

echo "Starting vulnerability assessment..."

# System vulnerability scan
lynis audit system --auditor "Security Team" --cronjob

# Docker image scanning
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image wazuh-mcp-server:latest

# Application dependency scan
safety check --full-report

# Network port scan
nmap -sS -O localhost

echo "Vulnerability assessment completed"
```

This comprehensive security guide provides the foundation for securing Wazuh MCP Server v3.0.0 in production environments. Regular security reviews and updates are essential to maintain a strong security posture.