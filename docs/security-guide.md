# Security Configuration Guide

Comprehensive security configuration and best practices for production deployment of Wazuh MCP Server.

## Security Architecture

The Wazuh MCP Server implements defense-in-depth security principles:

```
┌─────────────────────────────────────────┐
│            Client Layer                 │
│  ├─ Input Validation                   │
│  ├─ Rate Limiting                      │
│  └─ Authentication                     │
└─────────────────────────────────────────┘
               │
┌─────────────────────────────────────────┐
│          Transport Layer                │
│  ├─ SSL/TLS Encryption                 │
│  ├─ Certificate Validation             │
│  └─ Secure Headers                     │
└─────────────────────────────────────────┘
               │
┌─────────────────────────────────────────┐
│         Application Layer               │
│  ├─ JWT Token Management               │
│  ├─ Session Security                   │
│  ├─ Input Sanitization                 │
│  └─ SQL Injection Protection           │
└─────────────────────────────────────────┘
               │
┌─────────────────────────────────────────┐
│           Data Layer                    │
│  ├─ Secure Credential Storage          │
│  ├─ Audit Logging                      │
│  └─ Memory Protection                  │
└─────────────────────────────────────────┘
```

## Authentication & Authorization

### JWT Authentication (HTTP Mode)

**Configuration:**
```bash
# JWT settings in .env
JWT_SECRET_KEY=your-256-bit-secret-key-here
TOKEN_EXPIRY_MINUTES=30
REFRESH_TOKEN_EXPIRY_DAYS=7
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=15
```

**Secure JWT Key Generation:**
```bash
# Generate secure random key
python3 -c "import secrets; print(secrets.token_urlsafe(32))"

# Or use OpenSSL
openssl rand -base64 32
```

**Production JWT Configuration:**
```python
# Strong authentication settings
JWT_CONFIG = {
    "algorithm": "HS256",
    "secret_key": os.environ["JWT_SECRET_KEY"],
    "access_token_expire_minutes": 30,
    "refresh_token_expire_days": 7,
    "issuer": "wazuh-mcp-server",
    "audience": "mcp-clients"
}
```

### Password Security

**Requirements Enforced:**
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter  
- At least one number
- At least one special character
- Not in common password list
- No three consecutive identical characters

**Example Strong Passwords:**
```bash
# Good examples
MySecure2024Pass!@#
Wazuh$Security9876
Complex#MCP@Server2024

# Bad examples (will be rejected)
admin123
password
wazuh2024
```

### Wazuh API User Setup

**Create Dedicated API User:**
```bash
# 1. Create user with strong password
curl -k -X POST "https://your-wazuh:55000/security/users" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "mcp-api-user",
    "password": "YourComplexPassword2024!@#"
  }'

# 2. Create custom role with minimal permissions
curl -k -X POST "https://your-wazuh:55000/security/roles" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "mcp-readonly",
    "policies": [
      "agents:read",
      "alerts:read", 
      "rules:read",
      "manager:read"
    ]
  }'

# 3. Assign role to user
curl -k -X POST "https://your-wazuh:55000/security/users/mcp-api-user/roles" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{"role_ids": ["mcp-readonly"]}'
```

## SSL/TLS Configuration

### Production SSL Settings

**Recommended Configuration:**
```bash
# SSL/TLS settings
VERIFY_SSL=true
WAZUH_SSL_VERIFY=true
SSL_TIMEOUT=30
ALLOW_SELF_SIGNED=false
SSL_MIN_VERSION=TLSv1.2
SSL_CIPHERS=ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS
```

### Certificate Management

**Custom CA Certificate:**
```bash
# Add custom CA certificate
export CA_BUNDLE_PATH=/path/to/custom-ca.pem
export WAZUH_CA_BUNDLE_PATH=/path/to/wazuh-ca.pem

# Client certificate authentication
export CLIENT_CERT_PATH=/path/to/client.crt
export CLIENT_KEY_PATH=/path/to/client.key
```

**Certificate Validation Script:**
```bash
#!/bin/bash
# validate-ssl.sh - SSL certificate validation

WAZUH_HOST=${1:-$WAZUH_HOST}
WAZUH_PORT=${2:-55000}

echo "🔒 Validating SSL certificate for $WAZUH_HOST:$WAZUH_PORT"

# Check certificate validity
openssl s_client -connect $WAZUH_HOST:$WAZUH_PORT -servername $WAZUH_HOST < /dev/null 2>/dev/null | \
openssl x509 -noout -dates

# Check certificate chain
openssl s_client -connect $WAZUH_HOST:$WAZUH_PORT -showcerts < /dev/null 2>/dev/null | \
openssl x509 -noout -subject -issuer

# Test SSL connection
curl -I -s -o /dev/null -w "%{http_code}\n" https://$WAZUH_HOST:$WAZUH_PORT/
```

## Input Validation & Sanitization

### Built-in Protection

The server includes comprehensive input protection:

**SQL Injection Protection:**
```python
# Blocked patterns
SQL_PATTERNS = [
    r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|CREATE)\b)",
    r"(--|#|/\*|\*/)",
    r"(\bOR\b.*=.*)",
    r"(;.*\bEXEC\b)",
    r"(\bEXEC\b\s*\()",
    r"(CAST\s*\()",
    r"(CONVERT\s*\()"
]
```

**Command Injection Protection:**
```python
# Blocked characters
COMMAND_CHARS = ['`', '$', '&', '|', ';', '\n', '\r', '>', '<', '(', ')']

# Path traversal protection
PATH_TRAVERSAL = ['..', './', '/.']
```

**XSS Protection:**
```python
# HTML encoding for output
import html
safe_output = html.escape(user_input)

# Content Security Policy headers
SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Content-Type-Options": "nosniff", 
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block"
}
```

### Custom Validation Rules

**Agent ID Validation:**
```python
def validate_agent_id(agent_id: str) -> bool:
    """Validate agent ID format."""
    import re
    # Allow only alphanumeric, 3-8 characters
    return bool(re.match(r'^[0-9a-fA-F]{3,8}$', agent_id))
```

**IP Address Validation:**
```python
def validate_ip_address(ip: str) -> bool:
    """Validate IP address and prevent private IP queries."""
    import ipaddress
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Block private/local IPs for external queries
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_multicast)
    except ipaddress.AddressValueError:
        return False
```

## Rate Limiting & DDoS Protection

### Rate Limiting Configuration

**Production Settings:**
```bash
# Rate limiting
MAX_REQUESTS_PER_MINUTE=60
BURST_SIZE=10
WINDOW_SECONDS=60
ENABLE_PER_IP_LIMITING=true
ENABLE_PER_USER_LIMITING=true

# Advanced rate limiting
ADAPTIVE_RATE_LIMITING=true
RATE_LIMIT_ADAPTATION_FACTOR=0.8
RATE_LIMIT_ERROR_THRESHOLD=0.1
```

**Rate Limiting Strategies:**

1. **Token Bucket Algorithm:**
```python
# Allow burst requests with sustained rate
RateLimiter(
    max_tokens=60,      # Max requests per minute
    refill_rate=1.0,    # 1 request per second
    burst_limit=10      # Allow 10 request burst
)
```

2. **Sliding Window Algorithm:**
```python
# Time-based request tracking
SlidingWindowRateLimiter(
    max_requests=60,    # Max in window
    time_window=60,     # 60 second window
    per_identifier=True # Per IP/user limits
)
```

3. **Adaptive Rate Limiting:**
```python
# Automatically adjust based on error rates
AdaptiveRateLimiter(
    base_limit=60,
    adaptation_factor=0.8,  # Reduce by 20% on errors
    error_threshold=0.1     # 10% error rate threshold
)
```

### DDoS Protection

**Application-Level Protection:**
```bash
# Connection limits
MAX_CONNECTIONS=50
MAX_KEEPALIVE_CONNECTIONS=20
KEEPALIVE_EXPIRY=30

# Request timeouts
CONNECT_TIMEOUT=10
READ_TIMEOUT=30
WRITE_TIMEOUT=10
POOL_TIMEOUT=30
```

**Network-Level Protection (Recommended):**
```bash
# Use with reverse proxy (nginx/cloudflare)
# nginx.conf
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;
limit_req zone=api burst=20 nodelay;

# Connection limiting
limit_conn_zone $binary_remote_addr zone=addr:10m;
limit_conn addr 10;
```

## Audit Logging & Monitoring

### Security Audit Configuration

**Audit Events Logged:**
- Authentication attempts (success/failure)
- Authorization failures
- Rate limit violations
- Input validation failures
- API access patterns
- Configuration changes
- Security policy violations

**Audit Log Format:**
```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "event_type": "authentication",
  "severity": "INFO",
  "user_id": "mcp-user",
  "ip_address": "192.168.1.100",
  "user_agent": "MCP-Client/1.0",
  "action": "login_success",
  "resource": "/auth/login",
  "details": {
    "method": "jwt",
    "session_id": "abc123",
    "token_expires": "2024-01-01T12:30:00Z"
  },
  "correlation_id": "req_123456"
}
```

### Security Monitoring Setup

**Real-time Monitoring:**
```bash
# Monitor authentication failures
tail -f logs/audit.log | jq 'select(.event_type=="authentication" and .action=="login_failure")'

# Monitor rate limit violations
tail -f logs/audit.log | jq 'select(.event_type=="rate_limit")'

# Monitor input validation failures
tail -f logs/audit.log | jq 'select(.event_type=="validation_error")'
```

**Security Metrics Dashboard:**
```bash
# Authentication metrics
curl http://localhost:3000/metrics | grep auth_

# Rate limiting metrics  
curl http://localhost:3000/metrics | grep rate_limit_

# Security violations
curl http://localhost:3000/metrics | grep security_
```

## Secure Deployment

### Environment Security

**Secure Environment Variables:**
```bash
# Use strong, unique values
WAZUH_HOST=wazuh.company.com
WAZUH_USER=mcp-readonly-user
WAZUH_PASS=YourComplexPassword2024!@#

# JWT configuration
JWT_SECRET_KEY=$(openssl rand -base64 32)
TOKEN_EXPIRY_MINUTES=30

# Security settings
VERIFY_SSL=true
ENABLE_RATE_LIMITING=true
ENABLE_AUDIT_LOGGING=true
LOG_LEVEL=INFO
```

**File Permissions:**
```bash
# Secure configuration files
chmod 600 .env
chmod 600 config/*.json
chmod 755 wazuh-mcp-server

# Set proper ownership
chown mcp-user:mcp-group .env
chown -R mcp-user:mcp-group logs/
```

### Docker Security

**Secure Dockerfile Practices:**
```dockerfile
# Use non-root user
RUN groupadd -r wazuh && useradd -r -g wazuh -d /app -s /bin/bash wazuh
USER wazuh

# Minimal attack surface
FROM python:3.11-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl && rm -rf /var/lib/apt/lists/*

# Security scanning
LABEL security.scan="enabled"
```

**Container Security:**
```bash
# Run with security options
docker run -d \
  --name wazuh-mcp-server \
  --user 1000:1000 \
  --read-only \
  --tmpfs /tmp \
  --tmpfs /var/run \
  --security-opt=no-new-privileges:true \
  --cap-drop=ALL \
  --cap-add=NET_BIND_SERVICE \
  wazuh-mcp-server
```

### Network Security

**Firewall Configuration:**
```bash
# Allow only necessary ports
ufw allow 3000/tcp  # MCP HTTP port
ufw allow 55000/tcp # Wazuh API (to Wazuh server only)
ufw deny 22/tcp     # Disable SSH if not needed

# Restrict source IPs
ufw allow from 192.168.1.0/24 to any port 3000
```

**Reverse Proxy Security:**
```nginx
# nginx security configuration
server {
    listen 443 ssl http2;
    server_name mcp.company.com;
    
    # SSL configuration
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=31536000" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-XSS-Protection "1; mode=block" always;
    
    # Rate limiting
    limit_req zone=api burst=20 nodelay;
    limit_conn addr 10;
    
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Security Testing

### Security Validation Script

**Run Security Tests:**
```bash
# Production security validation
python3 validate-production.py --security

# Check for vulnerabilities
python3 scripts/security-scan.py

# Penetration testing checklist
bash scripts/pentest-checklist.sh
```

**Manual Security Tests:**
```bash
# Test authentication
curl -X POST http://localhost:3000/auth/login \
  -d '{"username":"invalid","password":"invalid"}' \
  -H "Content-Type: application/json"

# Test rate limiting
for i in {1..100}; do
  curl http://localhost:3000/health &
done

# Test input validation
curl http://localhost:3000/api/alerts \
  -d '{"agent_id":"../../etc/passwd"}' \
  -H "Content-Type: application/json"
```

### Vulnerability Scanning

**Automated Security Scanning:**
```bash
# Dependency vulnerability scan
pip-audit --requirement requirements.txt

# Docker image scanning
docker scan wazuh-mcp-server:latest

# SAST (Static Application Security Testing)
bandit -r src/

# Network security scan
nmap -sS -O localhost
```

## Incident Response

### Security Incident Procedures

**Immediate Response:**
1. **Identify** - Detect security event
2. **Contain** - Isolate affected systems
3. **Assess** - Determine impact and scope
4. **Notify** - Alert security team
5. **Document** - Preserve evidence

**Security Event Classification:**
- **P1 Critical**: Active breach, data compromise
- **P2 High**: Suspicious activity, failed attacks
- **P3 Medium**: Policy violations, misconfigurations
- **P4 Low**: Informational events, audit findings

### Automated Response

**Security Automation:**
```python
# Auto-block suspicious IPs
def handle_suspicious_activity(ip_address, event_count):
    if event_count > THRESHOLD:
        # Add to firewall block list
        subprocess.run(['ufw', 'deny', 'from', ip_address])
        
        # Log security event
        logger.security(f"Auto-blocked IP {ip_address} due to suspicious activity")
        
        # Alert security team
        send_security_alert(f"IP {ip_address} blocked automatically")
```

**Alerting Configuration:**
```bash
# Slack/Teams integration
SECURITY_WEBHOOK_URL=https://hooks.slack.com/services/xxx
ALERT_THRESHOLD_CRITICAL=5
ALERT_THRESHOLD_HIGH=10

# Email alerts
SMTP_HOST=smtp.company.com
SECURITY_EMAIL=security@company.com
```

## Compliance & Governance

### Security Policies

**Access Control Policy:**
- Principle of least privilege
- Regular access reviews
- Strong authentication requirements
- Session management controls

**Data Protection Policy:**
- Encryption at rest and in transit
- Secure credential storage
- Data retention policies
- Privacy protection measures

**Monitoring Policy:**
- Comprehensive audit logging
- Real-time monitoring
- Incident response procedures
- Regular security assessments

### Compliance Frameworks

**SOC 2 Type II:**
- Access controls
- System monitoring
- Data protection
- Incident response

**ISO 27001:**
- Security management system
- Risk assessment
- Security controls
- Continuous improvement

**NIST Cybersecurity Framework:**
- Identify assets and risks
- Protect against threats
- Detect security events
- Respond to incidents
- Recover from events

For specific compliance requirements, see the [Compliance Guide](compliance-guide.md).

## Security Best Practices Summary

### ✅ Production Security Checklist

- [ ] Strong authentication configured (JWT with secure keys)
- [ ] Rate limiting enabled and tuned
- [ ] SSL/TLS properly configured
- [ ] Input validation and sanitization enabled
- [ ] Audit logging configured
- [ ] Security monitoring set up
- [ ] Regular security updates applied
- [ ] Vulnerability scanning implemented
- [ ] Incident response procedures documented
- [ ] Security training completed
- [ ] Compliance requirements met
- [ ] Regular security assessments scheduled

### 🔒 Ongoing Security Maintenance

1. **Regular Updates**: Keep dependencies and system updated
2. **Security Monitoring**: Review logs and alerts daily
3. **Access Reviews**: Quarterly access and permission reviews
4. **Penetration Testing**: Annual security assessments
5. **Training**: Regular security awareness training
6. **Documentation**: Keep security procedures updated
7. **Backup & Recovery**: Test backup and recovery procedures

For additional security resources, see:
- [Security Architecture](security-architecture.md)
- [Threat Modeling](threat-modeling.md)
- [Security Testing](security-testing.md)
- [Incident Response Playbooks](incident-response.md)