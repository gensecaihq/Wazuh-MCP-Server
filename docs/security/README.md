# Security Configuration Guide

Comprehensive security hardening guide for Wazuh MCP Server v4.3.0 production deployments.

## 🔒 Security Overview

Wazuh MCP Server implements multiple layers of security:
- **Transport Security**: Streamable HTTP transport with Origin/CORS validation. The server itself listens on **plain HTTP** — terminate inbound TLS at a reverse proxy (see [TLS](#tls--https))
- **Authentication**: OAuth 2.0 (DCR optional, disabled by default), JWT bearer tokens, API key authentication on all endpoints
- **RBAC**: Per-tool scope enforcement (`wazuh:read` / `wazuh:write`). 14 active response tools require write scope. Read-only tokens can only query data
- **Authless Guardrails**: `AUTH_MODE=none` defaults to read-only. `AUTHLESS_ALLOW_WRITE=true` required for destructive operations
- **Output Sanitization**: Credentials, tokens, and API keys are redacted from alert data before returning to LLM clients
- **Log Sanitization**: Global `SanitizingLogFilter` redacts passwords, tokens, secrets from all server logs
- **Security Middleware**: Automatic security headers (X-Content-Type-Options, X-Frame-Options, CSP, HSTS)
- **Encryption**: TLS for outbound Wazuh Manager/Indexer connections (verified by default); inbound HTTPS is provided by the reverse proxy in front
- **Input Validation**: Comprehensive parameter validation — regex-based IDs, `ipaddress` module for IPs, shell metacharacter blocking for active response, Elasticsearch Query DSL (no string interpolation)
- **Rate Limiting**: Per-client sliding window with a short retry-after backoff (seconds until the oldest request leaves the window)
- **Audit Logging**: All destructive tool calls logged with client ID, session, and arguments via dedicated audit logger

## 🛡️ Security Architecture

### Security-by-Design Principles

1. **Zero Trust**: No implicit trust, verify everything
2. **Least Privilege**: Minimum required permissions
3. **Defense in Depth**: Multiple security layers
4. **Fail Secure**: Secure defaults, fail closed
5. **Audit Everything**: Comprehensive logging and monitoring

### Threat Model

**Mitigated Threats:**
- ✅ Unauthorized access (authentication enforced on all MCP endpoints including `/`, `/mcp`, `/sse`)
- ✅ Man-in-the-middle attacks (TLS encryption, security headers)
- ✅ Credential theft (constant-time hash comparison, secure storage practices)
- ✅ Injection attacks (comprehensive input validation with regex patterns)
- ✅ Privilege escalation (per-tool RBAC scope enforcement, authless mode read-only by default)
- ✅ Data leakage to LLMs (output sanitization redacts credentials from alert data)
- ✅ Brute force attacks (sliding-window rate limit with short backoff)
- ✅ Unauthorized active response (write tools require explicit `wazuh:write` scope with audit trail)
- ✅ Clickjacking/XSS (security middleware headers)

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

### OAuth 2.0 hardening

When `AUTH_MODE=oauth`, the authorization server enforces:

- **PKCE with `S256` is mandatory** — authorization codes without a valid `S256` challenge/verifier are rejected.
- **Single-use authorization codes** — a code is consumed atomically on exchange; replay fails.
- **Refresh-token rotation with replay detection** — every refresh issues a new refresh token; presenting a rotated (already-used) token revokes the entire grant (per OAuth BCP).
- **Revocation denylist** — revoked tokens are rejected even via the stateless-JWT fallback (`/oauth/revoke`, RFC 7009).
- **Scope bound to the client** — the granted scope is intersected with the client's registered scope, so a read-only client cannot self-grant `wazuh:write`.
- **Confidential-client authentication** — a client with a secret must present it at the token endpoint (omitting it is rejected, protecting refresh-token redemption).
- **Issuer integrity** — the issuer URL comes from `OAUTH_ISSUER_URL`, or is derived from the request only when the peer is in `TRUSTED_PROXIES` (prevents `x-forwarded-host` discovery poisoning). RFC 9207 `iss` is returned on the authorization response.
- **DCR off by default** — `OAUTH_ENABLE_DCR=false`; when enabled, registration validates redirect URIs (https, or http for loopback, no fragments).
- **Discovery** — `/.well-known/oauth-authorization-server` (RFC 8414) and `/.well-known/oauth-protected-resource` (RFC 9728); the latter is also advertised via the `WWW-Authenticate` header on 401s.

## 🔒 Encryption & TLS

### TLS Configuration

The server has **no built-in inbound HTTPS listener** — it speaks plain HTTP on `MCP_PORT`,
and inbound TLS (certificates, minimum TLS version, cipher suites, HSTS, client-cert auth)
is configured at the **reverse proxy** in front (nginx/Caddy/Traefik). The only TLS knobs the
server itself honors are for its **outbound** connections to Wazuh:

```bash
# .env — outbound TLS to the Wazuh Manager / Indexer
WAZUH_VERIFY_SSL=true            # verify the Manager cert (default)
WAZUH_ALLOW_SELF_SIGNED=false    # allow a self-signed Manager cert
WAZUH_INDEXER_VERIFY_SSL=true    # verify the Indexer cert (default)
WAZUH_INDEXER_SSL=true           # use HTTPS to the Indexer
```

For inbound TLS hardening, see your reverse proxy's documentation (a sample is in
`docs/nginx-reverse-proxy.conf`).

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

### Inbound TLS hardening (at the reverse proxy)

Enforce a minimum TLS version and strong ciphers on the proxy that terminates HTTPS in
front of the server — for example, in nginx:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!MD5;
ssl_prefer_server_ciphers on;
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
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

### Destructive-operation audit trail

Audit logging is **always on** — there is no enable flag. Every `wazuh:write` (active
response / rollback) tool call is emitted at WARNING level on the dedicated
`wazuh_mcp_server.audit` Python logger before the action runs. Route or persist it with
standard Python logging / your container's log driver (e.g. a file on a mounted volume,
syslog, or an OTLP shipper); the global `SanitizingLogFilter` redacts credentials from it.

#### Audit record format
Each record is a single WARNING line:

```
AUDIT: tool=wazuh_block_ip client=<api_key_id> session=<session_id> args={"ip_address":"10.0.0.9","cluster_id":"prod-eu"}
```

It captures the tool name, the authenticated client (API-key id), the session id, and the
call arguments — enough to answer "who did what, to which target, when" from timestamps.

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
curl http://localhost:3000/health

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
docker compose down

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