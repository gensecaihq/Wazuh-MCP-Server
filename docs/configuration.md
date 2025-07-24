# Configuration Guide

## Environment Variables

Configuration is handled through environment variables in a `.env` file.

### Required Settings

```bash
# Wazuh API Connection (REQUIRED)
WAZUH_API_URL=https://your-wazuh:55000
WAZUH_API_USERNAME=your-api-user
WAZUH_API_PASSWORD=your-api-password
WAZUH_API_VERIFY_SSL=true
```

### Server Settings

```bash
# Server Mode
MCP_SERVER_MODE=auto          # auto|stdio|remote
MCP_SERVER_PORT=8443          # HTTPS port for remote mode
MCP_TRANSPORT=sse             # Transport: stdio|http|sse

# Host binding
MCP_SERVER_HOST=0.0.0.0       # Bind address
```

### Security Configuration

```bash
# OAuth 2.0 Authentication
OAUTH_ENABLED=true            # Enable OAuth authentication
JWT_SECRET_KEY=               # Auto-generated if empty
JWT_EXPIRATION_HOURS=24       # Token expiration

# Admin User (auto-created)
ADMIN_USERNAME=admin
ADMIN_PASSWORD=admin
```

### Performance Settings

```bash
# Connection Limits
MAX_CONNECTIONS=1000          # Maximum concurrent connections
REQUEST_TIMEOUT=30            # Request timeout in seconds
WORKER_PROCESSES=4            # Number of worker processes

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS_PER_MINUTE=60
```

### Logging Configuration

```bash
# Log Settings
LOG_LEVEL=WARNING             # DEBUG|INFO|WARNING|ERROR
LOG_FORMAT=json               # json|text
LOG_TO_FILE=true              # Enable file logging
LOG_ROTATION_SIZE=100MB       # Log rotation size
LOG_RETENTION_DAYS=30         # Log retention period
```

### Feature Flags

```bash
# Core Features
ENABLE_METRICS=false          # Disable metrics endpoint
REDIS_ENABLED=false           # Use in-memory caching
SELF_CONTAINED=true           # Self-contained mode
AUTO_GENERATE_CONFIG=true     # Auto-generate missing configs
PRESERVE_V2_COMPATIBILITY=true # Maintain v2.0.0 compatibility
```

## Configuration Templates

### Development (.env.development)

```bash
# Wazuh API
WAZUH_API_URL=https://localhost:55000
WAZUH_API_USERNAME=wazuh
WAZUH_API_PASSWORD=wazuh
WAZUH_API_VERIFY_SSL=false

# Development settings
MCP_SERVER_MODE=stdio
LOG_LEVEL=DEBUG
OAUTH_ENABLED=false
DEBUG_MODE=true
```

### Production (.env.production)

```bash
# Wazuh API
WAZUH_API_URL=https://wazuh.internal:55000
WAZUH_API_USERNAME=mcp-api-user
WAZUH_API_PASSWORD=secure-password
WAZUH_API_VERIFY_SSL=true

# Production settings
MCP_SERVER_MODE=remote
MCP_SERVER_PORT=8443
LOG_LEVEL=WARNING
OAUTH_ENABLED=true
JWT_SECRET_KEY=your-secure-jwt-secret-key
MAX_CONNECTIONS=1000
WORKER_PROCESSES=4
```

## Docker Configuration

### Environment Variables in docker-compose.yml

```yaml
services:
  wazuh-mcp-server:
    environment:
      - WAZUH_API_URL=${WAZUH_API_URL}
      - WAZUH_API_USERNAME=${WAZUH_API_USERNAME}
      - WAZUH_API_PASSWORD=${WAZUH_API_PASSWORD}
      - MCP_SERVER_MODE=${MCP_SERVER_MODE:-auto}
      - LOG_LEVEL=${LOG_LEVEL:-WARNING}
```

### Volume Configuration

```yaml
volumes:
  - wazuh-mcp-config:/app/config:rw    # Configuration files
  - wazuh-mcp-logs:/app/logs:rw        # Log files
  - wazuh-mcp-data:/app/data:rw        # Data storage
```

## SSL/TLS Configuration

### Auto-Generated Certificates

By default, the server generates self-signed certificates automatically.

### Custom Certificates

```bash
# Place certificates in config directory
/app/config/ssl/cert.pem      # Certificate
/app/config/ssl/key.pem       # Private key
/app/config/ssl/ca.pem        # CA certificate (optional)

# Environment variables
SSL_ENABLED=true
SSL_CERT_PATH=/app/config/ssl/cert.pem
SSL_KEY_PATH=/app/config/ssl/key.pem
SSL_CA_PATH=/app/config/ssl/ca.pem
```

## Mode Configuration

### stdio Mode (v2.0.0 Compatible)

```bash
MCP_SERVER_MODE=stdio
# Used with Claude Desktop directly
# No HTTP server, no authentication
```

### Remote Mode (v3.0.0)

```bash
MCP_SERVER_MODE=remote
MCP_TRANSPORT=sse
MCP_SERVER_PORT=8443
OAUTH_ENABLED=true
# Full HTTP/SSE server with authentication
```

### Auto Mode (Recommended)

```bash
MCP_SERVER_MODE=auto
# Automatically detects best mode based on environment
# stdio if CLAUDE_DESKTOP_CONFIG present
# remote otherwise
```

## Wazuh API Configuration

### Create API User

```bash
# Create dedicated API user in Wazuh
curl -u admin:admin -k -X POST \
  "https://wazuh:55000/security/users" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "mcp-api-user",
    "password": "secure-password"
  }'
```

### Set Permissions

```bash
# Assign appropriate roles
curl -u admin:admin -k -X POST \
  "https://wazuh:55000/security/users/mcp-api-user/roles" \
  -H "Content-Type: application/json" \
  -d '{
    "role_ids": [1, 2, 3]
  }'
```

## Validation

### Configuration Validation

```bash
# Test configuration
python scripts/validate_setup.py

# Test Wazuh connection
python scripts/test_connection.py
```

### Health Check

```bash
# Check server health
curl -k https://localhost:8443/health

# Response should be:
{
  "status": "healthy",
  "version": "3.0.0",
  "mode": "remote",
  "tools": 26
}
```

## Troubleshooting

### Common Issues

1. **Invalid Wazuh Credentials**
   ```bash
   # Test manually
   curl -u user:pass https://wazuh:55000/security/user/authenticate
   ```

2. **SSL Certificate Issues**
   ```bash
   # Disable SSL verification for testing
   WAZUH_API_VERIFY_SSL=false
   ```

3. **Port Conflicts**
   ```bash
   # Check if port is in use
   netstat -tulpn | grep 8443
   
   # Use different port
   MCP_SERVER_PORT=8444
   ```

4. **Permission Errors**
   ```bash
   # Check file permissions
   ls -la config/
   
   # Fix permissions
   chmod 600 config/ssl/key.pem
   chmod 644 config/ssl/cert.pem
   ```

## Best Practices

### Security

- Use strong passwords for all accounts
- Generate cryptographically secure JWT secrets
- Enable SSL certificate verification
- Use dedicated API users with minimal permissions
- Regular key rotation

### Performance

- Adjust worker processes based on CPU cores
- Set appropriate connection limits
- Use caching for repeated queries
- Monitor resource usage

### Reliability

- Configure health checks
- Set up log rotation
- Monitor certificate expiration
- Implement backup procedures

## Example Configurations

### High Performance

```bash
WORKER_PROCESSES=8
MAX_CONNECTIONS=2000
REQUEST_TIMEOUT=60
CONNECTION_POOL_SIZE=100
```

### High Security

```bash
OAUTH_ENABLED=true
JWT_EXPIRATION_HOURS=1
RATE_LIMIT_REQUESTS_PER_MINUTE=30
LOG_LEVEL=INFO
AUDIT_LOGGING=true
```

### Development

```bash
MCP_SERVER_MODE=stdio
LOG_LEVEL=DEBUG
OAUTH_ENABLED=false
DEBUG_MODE=true
WAZUH_API_VERIFY_SSL=false
```