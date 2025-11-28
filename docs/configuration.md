# Configuration Guide

Complete configuration reference for Wazuh MCP Server v2.1.0.

## 📋 Configuration Overview

Wazuh MCP Server uses environment variables for configuration, loaded from:
1. `.env` file (recommended for development)
2. System environment variables (recommended for production)
3. Default values (built-in fallbacks)

## 🔧 Basic Configuration

### Required Settings

```bash
# Wazuh Server Connection
WAZUH_HOST=your-wazuh-server.com
WAZUH_PORT=55000
WAZUH_USER=your-username
WAZUH_PASS=your-password
```

### Minimal Working Configuration

Create `.env` with these minimal settings:

```bash
# Basic Wazuh Connection
WAZUH_HOST=localhost
WAZUH_PORT=55000
WAZUH_USER=wazuh
WAZUH_PASS=changeme

# Transport Configuration
MCP_TRANSPORT=stdio
```

## 💡 Complete Configuration Reference

### Wazuh Server API Configuration

```bash
# Wazuh Server Connection
WAZUH_HOST=your-wazuh-server.com          # Wazuh server hostname/IP
WAZUH_PORT=55000                          # Wazuh API port (default: 55000)
WAZUH_USER=your-username                  # Wazuh API username
WAZUH_PASS=your-password                  # Wazuh API password

# API Protocol
WAZUH_PROTOCOL=https                      # Protocol (http/https)
WAZUH_API_VERSION=v1                      # API version

# Authentication
WAZUH_AUTH_TYPE=basic                     # Authentication type (basic/jwt)
WAZUH_JWT_TOKEN=                          # JWT token (if using JWT auth)
```

### Wazuh Indexer Configuration

```bash
# Wazuh Indexer (OpenSearch/Elasticsearch)
WAZUH_INDEXER_HOST=your-indexer-host.com  # Indexer hostname/IP
WAZUH_INDEXER_PORT=9200                   # Indexer port (default: 9200)
WAZUH_INDEXER_USER=admin                  # Indexer username
WAZUH_INDEXER_PASS=admin                  # Indexer password
WAZUH_INDEXER_PROTOCOL=https              # Indexer protocol

# API Routing Configuration
USE_INDEXER_FOR_ALERTS=true               # Use Indexer for alerts (recommended)
USE_INDEXER_FOR_VULNERABILITIES=true     # Use Indexer for vulnerabilities
```

### SSL/TLS Configuration

```bash
# SSL Certificate Verification
VERIFY_SSL=true                           # Verify SSL certificates (recommended)
ALLOW_SELF_SIGNED=false                   # Allow self-signed certificates

# Custom Certificate Paths
CA_BUNDLE_PATH=/path/to/ca-bundle.crt     # Custom CA bundle
CLIENT_CERT_PATH=/path/to/client.crt      # Client certificate
CLIENT_KEY_PATH=/path/to/client.key       # Client private key

# SSL/TLS Version
MIN_TLS_VERSION=TLSv1.2                   # Minimum TLS version
SSL_TIMEOUT=30                            # SSL connection timeout (seconds)
```

### Logging Configuration

```bash
# Log Level
LOG_LEVEL=INFO                            # Log level (DEBUG/INFO/WARNING/ERROR)

# Log Output
LOG_FORMAT=json                           # Log format (json/text)
LOG_FILE=logs/wazuh-mcp-server.log       # Log file path
LOG_MAX_SIZE=100MB                        # Max log file size
LOG_BACKUP_COUNT=5                        # Number of backup log files

# Audit Logging
AUDIT_LOGGING=true                        # Enable audit logging
AUDIT_LOG_FILE=logs/audit.log            # Audit log file
```

### Performance Configuration

```bash
# Connection Pooling
MAX_CONNECTIONS=100                       # Maximum connections
CONNECTION_TIMEOUT=30                     # Connection timeout (seconds)
READ_TIMEOUT=60                          # Read timeout (seconds)

# Rate Limiting
RATE_LIMIT_REQUESTS=1000                 # Requests per minute
RATE_LIMIT_BURST=100                     # Burst requests allowed

# Caching
CACHE_TTL=300                            # Cache TTL (seconds)
CACHE_MAX_SIZE=1000                      # Maximum cache entries
```

### FastMCP Configuration

```bash
# Transport Settings
MCP_TRANSPORT=stdio                       # Transport type (stdio only)
MCP_SERVER_NAME=Wazuh MCP Server         # Server name
MCP_SERVER_VERSION=2.1.0                 # Server version

# Tool Configuration
ENABLE_SECURITY_TOOLS=true               # Enable security analysis tools
ENABLE_COMPLIANCE_TOOLS=true             # Enable compliance tools
ENABLE_VULNERABILITY_TOOLS=true          # Enable vulnerability tools
```

### Development Configuration

```bash
# Development Settings
DEBUG=false                              # Enable debug mode
DEVELOPMENT_MODE=false                   # Enable development features

# Testing
TEST_MODE=false                          # Enable test mode
MOCK_WAZUH_RESPONSES=false              # Use mock responses for testing
```

## 🏗️ Environment-Specific Configurations

### Development Environment

```bash
# .env.development
WAZUH_HOST=dev-wazuh-server.internal
WAZUH_PORT=55000
WAZUH_USER=dev-user
WAZUH_PASS=dev-password

# Relaxed SSL for development
VERIFY_SSL=false
ALLOW_SELF_SIGNED=true

# Verbose logging
LOG_LEVEL=DEBUG
DEBUG=true

# Development features
DEVELOPMENT_MODE=true
```

### Production Environment

```bash
# .env.production
WAZUH_HOST=prod-wazuh-server.company.com
WAZUH_PORT=55000
WAZUH_USER=mcp-service-account
WAZUH_PASS=very-secure-password

# Strict security
VERIFY_SSL=true
ALLOW_SELF_SIGNED=false
MIN_TLS_VERSION=TLSv1.3

# Production logging
LOG_LEVEL=INFO
AUDIT_LOGGING=true

# Performance optimization
MAX_CONNECTIONS=200
CACHE_TTL=600
```

### Testing Environment

```bash
# .env.testing
WAZUH_HOST=test-wazuh-server.internal
WAZUH_PORT=55000
WAZUH_USER=test-user
WAZUH_PASS=test-password

# Testing settings
TEST_MODE=true
MOCK_WAZUH_RESPONSES=false
LOG_LEVEL=DEBUG

# Reduced timeouts for faster tests
CONNECTION_TIMEOUT=10
READ_TIMEOUT=20
```

## 🔒 Security Best Practices

### Credential Management

**❌ Don't do this:**
```bash
# Hard-coded passwords in configuration files
WAZUH_PASS=my-secret-password
```

**✅ Do this instead:**
```bash
# Use environment variables
export WAZUH_PASS="$(cat /secure/wazuh-password)"

# Or use a secrets management system
WAZUH_PASS="$(/path/to/get-secret wazuh-password)"
```

### File Permissions

```bash
# Secure .env file permissions
chmod 600 .env
chown your-user:your-group .env

# Secure log directory
chmod 750 logs/
chown your-user:your-group logs/
```

### SSL/TLS Hardening

```bash
# Production SSL configuration
VERIFY_SSL=true
ALLOW_SELF_SIGNED=false
MIN_TLS_VERSION=TLSv1.3
SSL_TIMEOUT=10

# Use proper certificates
CA_BUNDLE_PATH=/etc/ssl/certs/ca-certificates.crt
CLIENT_CERT_PATH=/etc/wazuh-mcp/client.crt
CLIENT_KEY_PATH=/etc/wazuh-mcp/client.key
```

## 🎯 Configuration Validation

### Health Check Command

```bash
# Validate configuration
./bin/wazuh-mcp-server --health-check

# Validate with detailed output
./bin/wazuh-mcp-server --health-check --verbose
```

### Configuration Test Script

```bash
# Test configuration
python tools/validate_setup.py

# Test specific components
python tools/validate_setup.py --test-connection
python tools/validate_setup.py --test-ssl
python tools/validate_setup.py --test-auth
```

## 📝 Configuration Examples

### Example 1: Basic Setup

```bash
# .env
WAZUH_HOST=192.168.1.100
WAZUH_PORT=55000
WAZUH_USER=wazuh-api
WAZUH_PASS=secure-password
VERIFY_SSL=false
MCP_TRANSPORT=stdio
LOG_LEVEL=INFO
```

### Example 2: High Availability Setup

```bash
# .env
WAZUH_HOST=wazuh-cluster.company.com
WAZUH_PORT=55000
WAZUH_USER=mcp-service
WAZUH_PASS=complex-password

# Indexer for performance
WAZUH_INDEXER_HOST=wazuh-indexer.company.com
WAZUH_INDEXER_PORT=9200
USE_INDEXER_FOR_ALERTS=true

# Security hardening
VERIFY_SSL=true
MIN_TLS_VERSION=TLSv1.3
CA_BUNDLE_PATH=/etc/ssl/company-ca.crt

# Performance tuning
MAX_CONNECTIONS=500
CACHE_TTL=900
RATE_LIMIT_REQUESTS=2000
```

### Example 3: Multi-Tenant Setup

```bash
# .env.tenant1
WAZUH_HOST=tenant1-wazuh.company.com
WAZUH_USER=tenant1-mcp
WAZUH_PASS=tenant1-password
MCP_SERVER_NAME=Tenant1 Wazuh MCP
LOG_FILE=logs/tenant1-wazuh-mcp.log
```

## 🔄 Dynamic Configuration

### Environment Variable Overrides

Configuration precedence (highest to lowest):
1. Command-line arguments
2. System environment variables
3. `.env` file
4. Default values

```bash
# Override via environment variable
export WAZUH_HOST=new-server.com
./bin/wazuh-mcp-server --stdio

# Override via command line (if supported)
./bin/wazuh-mcp-server --wazuh-host=new-server.com --stdio
```

### Configuration Reloading

Currently, configuration changes require server restart:

```bash
# After changing .env file
pkill -f wazuh-mcp-server
./bin/wazuh-mcp-server --stdio
```

## 🐛 Troubleshooting Configuration

### Common Configuration Issues

#### Connection Issues
```bash
# Test connectivity
curl -k -u "user:pass" "https://wazuh-server:55000/"

# Check DNS resolution
nslookup wazuh-server.com

# Check firewall
telnet wazuh-server.com 55000
```

#### SSL Certificate Issues
```bash
# Test SSL certificate
openssl s_client -connect wazuh-server:55000 -servername wazuh-server

# Check certificate validity
openssl x509 -in certificate.crt -text -noout
```

#### Permission Issues
```bash
# Check file permissions
ls -la .env
ls -la logs/

# Fix permissions
chmod 600 .env
chmod 750 logs/
```

### Configuration Debugging

Enable debug logging:
```bash
LOG_LEVEL=DEBUG
DEBUG=true
```

Check configuration loading:
```bash
# Validate configuration syntax
python -c "from wazuh_mcp_server.config import WazuhConfig; config = WazuhConfig(); print('Configuration loaded successfully')"
```

## 🤖 Claude Desktop Integration

> **Important:** Claude Desktop supports remote MCP servers through the **Connectors UI**, not via `claude_desktop_config.json`. The JSON config file only supports local stdio-based MCP servers.

### Requirements

- **Claude Pro, Max, Team, or Enterprise plan** (custom connectors require paid plan)
- Server accessible via **HTTPS** (required for production)
- Feature is currently in **beta**

### Configuration Steps

1. **Deploy your server** with HTTPS enabled
2. Open Claude Desktop → **Settings** → **Connectors**
3. Click **"Add custom connector"**
4. Enter your server URL:
   - Streamable HTTP: `https://your-domain.com/mcp`
   - Legacy SSE: `https://your-domain.com/sse`
5. Configure authentication in **Advanced settings** if needed
6. Click **Connect**

### Authentication Modes

Configure via `AUTH_MODE` environment variable:

| Mode | Value | Description |
|------|-------|-------------|
| **OAuth** | `oauth` | OAuth 2.0 with DCR (recommended for Claude Desktop) |
| **Bearer** | `bearer` | JWT token authentication (default) |
| **Authless** | `none` | No authentication (development only) |

**OAuth Mode (`AUTH_MODE=oauth`):**
- Discovery: `/.well-known/oauth-authorization-server`
- Endpoints: `/oauth/authorize`, `/oauth/token`, `/oauth/register`
- Claude Desktop connects seamlessly via DCR

**Bearer Mode (`AUTH_MODE=bearer`):**
```bash
# Get JWT token
curl -X POST https://your-server.com/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "wazuh_your-api-key"}'
```

**Authless Mode (`AUTH_MODE=none`):**
- No authentication required
- For development/testing only

### Common Error

If you see this error:
```
Could not load app settings
"path": ["mcpServers", "wazuh-security", "command"]
"message": "Required"
```

**Cause:** You edited `claude_desktop_config.json` with `url` + `headers` format.

**Solution:** Use the **Connectors UI** instead. The JSON config only supports local stdio servers.

For detailed instructions, see the [Claude Desktop Integration](../README.md#-claude-desktop-integration) section in the main README.

## 📞 Getting Help

For configuration issues:

1. **Check [Troubleshooting Guide](troubleshooting/README.md)**
2. **Run health check**: `./bin/wazuh-mcp-server --health-check`
3. **Validate setup**: `python tools/validate_setup.py`
4. **Check logs**: `tail -f logs/wazuh-mcp-server.log`

---

**Next Steps**: See [Security Guide](security/README.md) for security hardening or [API Reference](api/README.md) for available tools.