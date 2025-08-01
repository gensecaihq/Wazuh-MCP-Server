# Security Configuration Guide

Comprehensive security hardening guide for Wazuh MCP Server v2.1.0 production deployments.

## 🔒 Security Overview

Wazuh MCP Server implements multiple layers of security:
- **Transport Security**: STDIO-only transport eliminates network attack vectors
- **Authentication**: Robust credential management and token-based authentication
- **Encryption**: TLS/SSL encryption for all API communications
- **Input Validation**: Comprehensive parameter validation and sanitization
- **Audit Logging**: Complete audit trail for security events

## 🛡️ Security Architecture

### Security-by-Design Principles

1. **Zero Trust**: No implicit trust, verify everything
2. **Least Privilege**: Minimum required permissions
3. **Defense in Depth**: Multiple security layers
4. **Fail Secure**: Secure defaults, fail closed
5. **Audit Everything**: Comprehensive logging and monitoring

### Threat Model

**Mitigated Threats:**
- ✅ Network-based attacks (STDIO transport only)
- ✅ Man-in-the-middle attacks (TLS encryption)
- ✅ Credential theft (secure storage practices)
- ✅ Injection attacks (input validation)
- ✅ Privilege escalation (least privilege)

**Residual Risks:**
- ⚠️ Local system compromise
- ⚠️ Wazuh server compromise
- ⚠️ Claude Desktop compromise

## 🔐 Authentication & Authorization

### Wazuh Server Authentication

#### Basic Authentication (Default)
```bash
# .env
WAZUH_AUTH_TYPE=basic
WAZUH_USER=secure-service-account
WAZUH_PASS=complex-password-123!@#
```

**Security Requirements:**
- Use dedicated service account
- Strong password (12+ characters, mixed case, numbers, symbols)
- Regular password rotation (90 days recommended)

#### JWT Token Authentication (Recommended)
```bash
# .env
WAZUH_AUTH_TYPE=jwt
WAZUH_JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

**Security Benefits:**
- Short-lived tokens (configurable expiration)
- Automatic token refresh
- Reduced credential exposure

### Service Account Configuration

#### Create Dedicated Service Account
```bash
# On Wazuh server
curl -k -X POST "https://wazuh-server:55000/security/users" \
  -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "mcp-service",
    "password": "SecurePassword123!@#",
    "roles": ["readonly", "mcp_custom_role"]
  }'
```

#### Minimum Required Permissions
```json
{
  "name": "mcp_custom_role",
  "permissions": {
    "agents:read": ["*"],
    "alerts:read": ["*"],
    "vulnerabilities:read": ["*"],
    "rules:read": ["*"],
    "cluster:read": ["*"],
    "stats:read": ["*"]
  }
}
```

## 🔒 Encryption & TLS

### TLS Configuration

#### Production TLS Settings
```bash
# .env - Production
VERIFY_SSL=true
ALLOW_SELF_SIGNED=false
MIN_TLS_VERSION=TLSv1.3
SSL_TIMEOUT=10
```

#### Certificate Management
```bash
# Custom CA certificate
CA_BUNDLE_PATH=/etc/ssl/certs/company-ca.crt

# Client certificate authentication
CLIENT_CERT_PATH=/etc/wazuh-mcp/client.crt
CLIENT_KEY_PATH=/etc/wazuh-mcp/client.key
```

### Certificate Best Practices

#### Certificate Validation
```bash
# Verify certificate validity
openssl x509 -in certificate.crt -text -noout

# Check certificate chain
openssl verify -CAfile ca-bundle.crt certificate.crt

# Test TLS connection
openssl s_client -connect wazuh-server:55000 -servername wazuh-server
```

#### Certificate Rotation
```bash
# Automated certificate rotation script
#!/bin/bash
CERT_PATH="/etc/wazuh-mcp/client.crt"
if [ $(openssl x509 -in "$CERT_PATH" -noout -checkend 2592000) ]; then
    echo "Certificate expires within 30 days, rotating..."
    # Certificate rotation logic here
fi
```

### SSL/TLS Hardening

#### Disable Weak Protocols
```bash
# Force TLS 1.3 only
MIN_TLS_VERSION=TLSv1.3

# Disable weak ciphers (if supported)
SSL_CIPHERS="ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
```

## 🔐 Credential Security

### Environment Variable Security

#### Secure Credential Storage
```bash
# ❌ DON'T: Store credentials in files
WAZUH_PASS=my-password

# ✅ DO: Use secure credential sources
WAZUH_PASS="$(cat /run/secrets/wazuh-password)"
WAZUH_PASS="$(vault kv get -field=password secret/wazuh)"
WAZUH_PASS="$(/usr/local/bin/get-credential wazuh-password)"
```

#### File Permissions
```bash
# Secure .env file
chmod 600 .env
chown root:wazuh-mcp .env

# Secure credential files
chmod 400 /run/secrets/wazuh-password
chown root:root /run/secrets/wazuh-password
```

### Secrets Management Integration

#### HashiCorp Vault
```bash
# Install Vault agent
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo apt-key add -
sudo apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main"
sudo apt-get update && sudo apt-get install vault

# Retrieve secret
export WAZUH_PASS="$(vault kv get -field=password secret/wazuh/mcp-service)"
```

#### AWS Secrets Manager
```bash
# Retrieve from AWS Secrets Manager
export WAZUH_PASS="$(aws secretsmanager get-secret-value --secret-id wazuh/mcp-password --query SecretString --output text)"
```

## 🛡️ Input Validation & Sanitization

### Parameter Validation

#### Pydantic Models
```python
# Built-in validation
class AlertQuery(BaseModel):
    limit: int = Field(default=100, ge=1, le=1000)
    rule_id: Optional[str] = Field(None, regex=r'^[0-9]+$')
    level: Optional[str] = Field(None, regex=r'^[0-9]+\+?$')
    agent_id: Optional[str] = Field(None, regex=r'^[0-9]+$')
```

#### Custom Validation
```python
@validator('timestamp_start')
def validate_timestamp(cls, v):
    if v and not re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$', v):
        raise ValueError('Invalid timestamp format')
    return v
```

### SQL Injection Prevention
```python
# Parameterized queries (built-in protection)
query = {
    "bool": {
        "must": [
            {"term": {"agent.id": sanitize_agent_id(agent_id)}},
            {"range": {"timestamp": {"gte": sanitize_timestamp(start_time)}}}
        ]
    }
}
```

## 📊 Audit Logging

### Security Event Logging

#### Enable Audit Logging
```bash
# .env
AUDIT_LOGGING=true
AUDIT_LOG_FILE=logs/security-audit.log
AUDIT_LOG_LEVEL=INFO
```

#### Audit Event Types
- Authentication attempts (success/failure)
- Authorization checks
- Configuration changes
- Tool usage and parameters
- Error conditions
- Connection events

#### Audit Log Format
```json
{
  "timestamp": "2024-01-01T12:00:00Z",
  "event_type": "authentication",
  "result": "success",
  "user": "mcp-service",
  "source_ip": "127.0.0.1",
  "tool": "get_wazuh_alerts",
  "parameters": {"limit": 100, "level": "12+"},
  "response_time": 0.25
}
```

### Log Security

#### Log Integrity
```bash
# Secure log files
chmod 640 logs/security-audit.log
chown root:wazuh-mcp logs/security-audit.log

# Log rotation with integrity
/usr/sbin/logrotate -s /var/lib/logrotate/logrotate.state /etc/logrotate.d/wazuh-mcp
```

#### Log Monitoring
```bash
# Monitor for security events
tail -f logs/security-audit.log | grep -E "(authentication|authorization|error)"

# SIEM integration
rsyslog -f /etc/rsyslog.d/wazuh-mcp.conf
```

## 🔍 Security Monitoring

### Health Checks

#### Security Health Validation
```bash
# Run security-focused health check
./bin/wazuh-mcp-server --health-check --security

# Expected security checks:
# ✅ ssl_config: SSL verification enabled
# ✅ credentials: Secure credential storage
# ✅ permissions: Proper file permissions
# ✅ audit_logging: Audit logging enabled
```

### Threat Detection

#### Anomaly Detection
```python
# Monitor for unusual patterns
- High error rates
- Authentication failures
- Unusual query patterns
- Performance anomalies
- Connection from new sources
```

#### Alerting Rules
```bash
# Security alerts
if grep -q "authentication.*failure" logs/security-audit.log; then
    echo "ALERT: Authentication failures detected" | mail -s "Security Alert" admin@company.com
fi
```

## 🚨 Incident Response

### Security Incident Procedures

#### Immediate Response
1. **Isolate**: Stop the MCP server
2. **Assess**: Check logs for compromise indicators
3. **Contain**: Revoke credentials if necessary
4. **Investigate**: Analyze security logs
5. **Recover**: Restore from secure backup

#### Emergency Commands
```bash
# Emergency shutdown
pkill -f wazuh-mcp-server

# Revoke API access
curl -k -X DELETE "https://wazuh-server:55000/security/users/mcp-service/tokens" \
  -H "Authorization: Bearer $ADMIN_TOKEN"

# Check for compromise
grep -E "(error|failure|unauthorized)" logs/security-audit.log | tail -100
```

## 🔒 Compliance & Standards

### Security Standards Compliance

#### SOC 2 Type II
- ✅ Access controls implemented
- ✅ Audit logging enabled
- ✅ Encryption in transit
- ✅ Secure credential management

#### ISO 27001
- ✅ Information security management
- ✅ Risk assessment procedures
- ✅ Access control measures
- ✅ Incident response procedures

#### NIST Cybersecurity Framework
- ✅ Identify: Asset and risk inventory
- ✅ Protect: Security controls implementation
- ✅ Detect: Monitoring and detection
- ✅ Respond: Incident response procedures
- ✅ Recover: Business continuity planning

### Compliance Verification

#### Security Assessment Checklist
```markdown
- [ ] TLS 1.3 enabled and enforced
- [ ] Strong authentication implemented
- [ ] Service account with minimal privileges
- [ ] Audit logging enabled and monitored
- [ ] File permissions properly configured
- [ ] Credentials stored securely
- [ ] Regular security updates applied
- [ ] Incident response procedures documented
```

## 🔧 Security Tools

### Security Validation Scripts

#### Automated Security Scan
```bash
#!/bin/bash
# security-scan.sh
echo "Running Wazuh MCP Server security scan..."

# Check file permissions
echo "Checking file permissions..."
find . -name "*.env" -exec ls -la {} \;

# Check TLS configuration
echo "Testing TLS configuration..."
python tools/validate_setup.py --test-ssl

# Check for secrets in files
echo "Scanning for hardcoded secrets..."
grep -r "password\|secret\|key" . --exclude-dir=venv --exclude="*.md"
```

#### Security Hardening Script
```bash
#!/bin/bash
# harden-security.sh
echo "Applying security hardening..."

# Set secure file permissions
chmod 600 .env
chmod 750 logs/
chmod 600 logs/*.log

# Update system packages
sudo apt update && sudo apt upgrade -y

# Configure firewall
sudo ufw allow out 55000/tcp  # Wazuh server
sudo ufw deny in 55000/tcp    # Block incoming
```

## 📞 Security Support

### Security Issues
- **Security vulnerabilities**: Report privately to security@company.com
- **Configuration issues**: Check [Configuration Guide](../configuration.md)
- **Incident response**: Follow documented procedures

### Security Resources
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [Wazuh Security Documentation](https://documentation.wazuh.com/current/user-manual/api/security.html)

---

**Security is everyone's responsibility.** Follow these guidelines to maintain a secure deployment and protect your organization's security data.