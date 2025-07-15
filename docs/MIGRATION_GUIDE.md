# Migration Guide

## Overview

This guide helps you migrate from previous versions of Wazuh MCP Server to take advantage of new features and improvements while maintaining backward compatibility.

## Migration Paths

### From v2.0.0 to v3.0.0 (Current)

#### Pre-Migration Checklist
- [ ] Backup your current configuration
- [ ] Test new installation in development environment
- [ ] Verify Wazuh API compatibility
- [ ] Check Docker environment if using containerization
- [ ] Review security requirements for OAuth2 setup

#### Migration Steps

1. **Backup Current Installation**
   ```bash
   cp -r /path/to/current/installation /path/to/backup
   ```

2. **Install v3.0.0**
   ```bash
   git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
   cd Wazuh-MCP-Server
   python3 scripts/install.py
   ```

3. **Migrate Configuration**
   ```bash
   # Copy your existing .env file
   cp /path/to/backup/.env .
   
   # Add new v3.0.0 configuration options
   cat >> .env << 'EOF'
   # v3.0.0 Remote MCP Configuration
   MCP_SERVER_HOST=0.0.0.0
   MCP_SERVER_PORT=8443
   MCP_TRANSPORT=sse
   
   # OAuth2 Authentication (optional for remote access)
   OAUTH_ENABLED=false
   JWT_SECRET_KEY=your-secret-key
   OAUTH_CLIENT_ID=wazuh-mcp-client
   OAUTH_CLIENT_SECRET=your-client-secret
   
   # Monitoring
   ENABLE_METRICS=true
   METRICS_PORT=9090
   EOF
   ```

4. **Choose Your Deployment Method**
   
   **Option A: Keep stdio mode (no changes needed)**
   ```bash
   # Continue using stdio mode as before
   python3 -m wazuh_mcp_server.main --stdio
   ```
   
   **Option B: Enable remote MCP server**
   ```bash
   # Start remote server
   python3 -m wazuh_mcp_server.remote_server --transport sse
   ```
   
   **Option C: Deploy with Docker**
   ```bash
   # Use Docker Compose for production
   docker-compose up -d
   ```

5. **Test Migration**
   ```bash
   # Run validation script
   python scripts/validate_setup.py
   
   # Test remote server (if enabled)
   curl -f http://localhost:8443/health
   ```

#### New Features in v3.0.0
- **Remote MCP Server**: HTTP/SSE transport for remote access
- **OAuth2 Authentication**: Enterprise-grade security with JWT tokens
- **Docker Deployment**: Production-ready containerization
- **High Availability**: Load balancing and auto-recovery
- **Production Monitoring**: Prometheus + Grafana stack
- **Security Hardening**: Audit logging and rate limiting

#### Breaking Changes
- None - v3.0.0 is fully backward compatible with v2.0.0
- All existing stdio configurations continue to work unchanged

### From v1.0.0 to v3.0.0 (Direct Migration)

#### Pre-Migration Checklist
- [ ] Backup your current configuration
- [ ] Test new installation in development environment
- [ ] Verify Wazuh API compatibility
- [ ] Check Python version compatibility (3.9+)
- [ ] Review new security features

#### Migration Steps

1. **Backup Current Installation**
   ```bash
   cp -r /path/to/current/installation /path/to/backup
   ```

2. **Install v3.0.0**
   ```bash
   git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
   cd Wazuh-MCP-Server
   python3 scripts/install.py
   ```

3. **Migrate Configuration**
   ```bash
   # Copy your existing .env file
   cp /path/to/backup/.env .
   
   # Add new configuration options
   cat >> .env << 'EOF'
   # v2.0.0 Features
   ENABLE_PHASE5_ENHANCEMENTS=true
   CACHE_TTL=300
   CONTEXT_AGGREGATION_DEPTH=3
   
   # v3.0.0 Features
   MCP_SERVER_HOST=0.0.0.0
   MCP_SERVER_PORT=8443
   MCP_TRANSPORT=sse
   OAUTH_ENABLED=false
   ENABLE_METRICS=true
   METRICS_PORT=9090
   EOF
   ```

4. **Test Migration**
   ```bash
   # Run validation script
   python scripts/validate_setup.py
   
   # Test all new features
   python scripts/test_v3_features.py
   ```

#### New Features Gained
- **All v2.0.0 features**: 12 additional tools, Phase 5 enhancements, factory architecture
- **All v3.0.0 features**: Remote MCP, OAuth2, Docker deployment, monitoring

### From v1.0.0 to v2.0.0 (Legacy)

#### Automatic Migration (Recommended)

1. **Update Code**
   ```bash
   cd /path/to/Wazuh-MCP-Server
   git pull origin main
   ```

2. **Run Migration Script**
   ```bash
   ./scripts/migrate_v1_to_v2.sh
   ```

3. **Restart Claude Desktop**
   - Close Claude Desktop completely
   - Reopen Claude Desktop
   - Test with: "Show me recent security alerts"

#### Manual Migration

1. **Update Claude Desktop Configuration**
   
   **Before (v1.0.0)**:
   ```json
   {
     "mcpServers": {
       "wazuh": {
         "command": "/path/to/Wazuh-MCP-Server/mcp_wrapper.sh",
         "args": ["--stdio"]
       }
     }
   }
   ```

   **After (v2.0.0)**:
   ```json
   {
     "mcpServers": {
       "wazuh": {
         "command": "/path/to/Wazuh-MCP-Server/scripts/mcp_wrapper.sh",
         "args": ["--stdio"]
       }
     }
   }
   ```

2. **Update Script Permissions**
   ```bash
   cd /path/to/Wazuh-MCP-Server
   chmod +x scripts/mcp_wrapper.sh
   chmod +x scripts/test_wrapper.sh
   ```

## Claude Desktop Configuration Migration

### Stdio Mode (No Changes Required)

All existing configurations continue to work:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "/path/to/Wazuh-MCP-Server/scripts/mcp_wrapper.sh",
      "args": ["--stdio"]
    }
  }
}
```

### Remote MCP Configuration (v3.0.0)

For remote access, update your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "wazuh": {
      "type": "url",
      "url": "https://your-server:8443/sse",
      "name": "wazuh-mcp",
      "authorization": {
        "type": "oauth2",
        "authorization_url": "https://your-server:8443/oauth/authorize",
        "token_url": "https://your-server:8443/oauth/token",
        "client_id": "wazuh-mcp-client",
        "scopes": ["read:alerts", "read:agents", "read:vulnerabilities"]
      }
    }
  }
}
```

## Production Deployment Migration

### From Development to Production

#### Step 1: Environment Configuration
```bash
# Create production environment
cat > .env.production << 'EOF'
# Production Configuration
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=INFO

# Wazuh Configuration
WAZUH_API_URL=https://your-wazuh-manager:55000
WAZUH_API_USERNAME=wazuh-mcp-api
WAZUH_API_PASSWORD=your-secure-password
WAZUH_API_VERIFY_SSL=true
WAZUH_ALLOW_SELF_SIGNED=false

# OAuth2 Security
OAUTH_ENABLED=true
JWT_SECRET_KEY=$(openssl rand -base64 32)
OAUTH_CLIENT_ID=wazuh-mcp-client
OAUTH_CLIENT_SECRET=$(openssl rand -base64 32)

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090
PROMETHEUS_RETENTION_TIME=15d

# Security
ENABLE_AUDIT_LOG=true
RATE_LIMIT_ENABLED=true
RATE_LIMIT_REQUESTS=100
RATE_LIMIT_WINDOW=3600
EOF
```

#### Step 2: Docker Deployment
```bash
# Deploy with high availability
docker-compose -f docker-compose.ha.yml up -d

# Verify deployment
docker-compose -f docker-compose.ha.yml ps
curl -f https://localhost:8443/health
```

## Configuration Migration Details

### Environment Variables

#### v1.0.0 → v3.0.0 Complete Migration
```env
# Original v1.0.0 variables (keep unchanged)
WAZUH_HOST=your-wazuh-server.com
WAZUH_USER=your-username
WAZUH_PASS=your-password
WAZUH_PORT=55000
VERIFY_SSL=true
DEBUG=false

# New v2.0.0 variables (optional)
ENABLE_PHASE5_ENHANCEMENTS=true
CACHE_TTL=300
CONTEXT_AGGREGATION_DEPTH=3
ENABLE_PARALLEL_PROCESSING=true
MAX_CONCURRENT_REQUESTS=10

# New v3.0.0 variables (optional)
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8443
MCP_TRANSPORT=sse
OAUTH_ENABLED=false
JWT_SECRET_KEY=your-secret-key
OAUTH_CLIENT_ID=wazuh-mcp-client
OAUTH_CLIENT_SECRET=your-client-secret
ENABLE_METRICS=true
METRICS_PORT=9090
LOG_FORMAT=json
ENABLE_AUDIT_LOG=true
```

#### v2.0.0 → v3.0.0 Incremental Migration
```env
# Keep all existing v2.0.0 variables
# Add only new v3.0.0 variables

# Remote MCP Configuration
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8443
MCP_TRANSPORT=sse

# Authentication (optional)
OAUTH_ENABLED=false
JWT_SECRET_KEY=your-secret-key
OAUTH_CLIENT_ID=wazuh-mcp-client
OAUTH_CLIENT_SECRET=your-client-secret

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090

# Security
ENABLE_AUDIT_LOG=true
RATE_LIMIT_ENABLED=true
```

## Testing Migration

### Validation Steps

1. **Basic Functionality Test**
   ```bash
   # Test stdio mode (should work unchanged)
   python3 -m wazuh_mcp_server.main --stdio
   
   # Test in Claude Desktop
   # Try: "Show me recent security alerts"
   ```

2. **New Features Test**
   ```bash
   # Test remote server
   python3 -m wazuh_mcp_server.remote_server --transport sse
   
   # Test health endpoint
   curl -f http://localhost:8443/health
   
   # Test metrics
   curl -f http://localhost:9090/metrics
   ```

3. **Integration Test**
   ```bash
   # Run comprehensive validation
   python scripts/validate_setup.py --comprehensive
   
   # Test all tools
   python scripts/test_all_tools.py
   ```

### Rollback Procedure

If migration fails, you can rollback:

```bash
# Stop current services
docker-compose down  # if using Docker
# or
pkill -f wazuh_mcp_server

# Restore from backup
rm -rf /path/to/current/installation
mv /path/to/backup /path/to/current/installation

# Restart services
cd /path/to/current/installation
python3 -m wazuh_mcp_server.main --stdio
```

## Post-Migration Optimization

### Performance Tuning

1. **Enable All Optimizations**
   ```env
   # Phase 5 enhancements
   ENABLE_PHASE5_ENHANCEMENTS=true
   CACHE_TTL=300
   CONTEXT_AGGREGATION_DEPTH=3
   
   # Performance optimization
   ENABLE_PARALLEL_PROCESSING=true
   MAX_CONCURRENT_REQUESTS=10
   ENABLE_INTELLIGENT_CACHING=true
   MAX_CACHE_SIZE=1000
   ```

2. **Monitor Performance**
   ```bash
   # Check metrics
   curl http://localhost:9090/metrics
   
   # Monitor with Grafana (if using Docker)
   # Access: http://localhost:3000
   ```

### Security Hardening

1. **Enable Security Features**
   ```env
   # OAuth2 authentication
   OAUTH_ENABLED=true
   JWT_SECRET_KEY=$(openssl rand -base64 32)
   
   # Rate limiting
   RATE_LIMIT_ENABLED=true
   RATE_LIMIT_REQUESTS=100
   RATE_LIMIT_WINDOW=3600
   
   # Audit logging
   ENABLE_AUDIT_LOG=true
   LOG_FORMAT=json
   ```

2. **SSL/TLS Configuration**
   ```env
   # Production SSL settings
   WAZUH_API_VERIFY_SSL=true
   WAZUH_ALLOW_SELF_SIGNED=false
   SSL_CERT_PATH=/path/to/server.crt
   SSL_KEY_PATH=/path/to/server.key
   ```

## Feature Adoption Guide

### Phase 1: Basic Migration (Week 1)
- Complete migration to v3.0.0
- Verify all existing functionality
- Test new tools in development

### Phase 2: Remote Access (Week 2)
- Enable remote MCP server
- Configure OAuth2 authentication
- Test remote access from Claude Code

### Phase 3: Production Deployment (Week 3)
- Deploy with Docker Compose
- Configure monitoring and alerting
- Implement backup procedures

### Phase 4: Advanced Features (Week 4)
- Enable high availability
- Configure advanced security features
- Optimize performance settings

## Common Issues and Solutions

### Migration Issues

#### Issue: "Module not found" errors
**Solution**: Ensure all dependencies are properly installed
```bash
pip install -r requirements.txt
```

#### Issue: OAuth2 authentication not working
**Solution**: Check OAuth2 configuration and client setup
```bash
# Validate OAuth2 setup
python scripts/validate_oauth2.py

# Test token generation
curl -X POST http://localhost:8443/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=wazuh-mcp-client&client_secret=your-secret"
```

#### Issue: Docker containers not starting
**Solution**: Check Docker configuration and logs
```bash
# Check container status
docker-compose ps

# Check logs
docker-compose logs -f wazuh-mcp-server

# Restart services
docker-compose restart
```

#### Issue: Performance degradation
**Solution**: Check cache configuration and enable optimizations
```bash
# Check cache status
python scripts/check_cache_status.py

# Enable optimizations
echo "ENABLE_OPTIMIZATIONS=true" >> .env
```

### Troubleshooting

#### Configuration Issues
```bash
# Validate configuration
python scripts/validate_setup.py

# Check for missing variables
python scripts/check_env_vars.py

# Test Wazuh connectivity
python scripts/test_wazuh_connection.py
```

#### Performance Issues
```bash
# Check system resources
python scripts/check_system_resources.py

# Optimize settings
python scripts/optimize_settings.py

# Monitor metrics
curl http://localhost:9090/metrics
```

#### Security Issues
```bash
# Check security configuration
python scripts/validate_security.py

# Test authentication
python scripts/test_authentication.py

# Review audit logs
tail -f /var/log/wazuh-mcp-server/audit.log
```

## Migration Scripts

### Automated Migration Script

```bash
#!/bin/bash
# migrate_to_v3.sh

set -euo pipefail

echo "Starting migration to Wazuh MCP Server v3.0.0"

# Backup current installation
if [ -d "/opt/wazuh-mcp-server" ]; then
    echo "Backing up current installation..."
    cp -r /opt/wazuh-mcp-server /opt/wazuh-mcp-server.backup.$(date +%Y%m%d_%H%M%S)
fi

# Clone v3.0.0
echo "Downloading v3.0.0..."
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git /opt/wazuh-mcp-server-v3
cd /opt/wazuh-mcp-server-v3

# Install dependencies
echo "Installing dependencies..."
python3 scripts/install.py

# Migrate configuration
if [ -f "/opt/wazuh-mcp-server/.env" ]; then
    echo "Migrating configuration..."
    cp /opt/wazuh-mcp-server/.env .env
    
    # Add new v3.0.0 variables
    cat >> .env << 'EOF'
# v3.0.0 Configuration
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8443
MCP_TRANSPORT=sse
OAUTH_ENABLED=false
ENABLE_METRICS=true
METRICS_PORT=9090
EOF
fi

# Validate migration
echo "Validating migration..."
python scripts/validate_setup.py

echo "Migration completed successfully!"
echo "To start using v3.0.0:"
echo "  cd /opt/wazuh-mcp-server-v3"
echo "  python3 -m wazuh_mcp_server.main --stdio"
```

### Configuration Update Script

```bash
#!/bin/bash
# update_config_v3.sh

set -euo pipefail

ENV_FILE="${1:-.env}"

echo "Updating configuration for v3.0.0..."

# Add v3.0.0 variables if not present
if ! grep -q "MCP_SERVER_HOST" "$ENV_FILE"; then
    cat >> "$ENV_FILE" << 'EOF'

# v3.0.0 Remote MCP Configuration
MCP_SERVER_HOST=0.0.0.0
MCP_SERVER_PORT=8443
MCP_TRANSPORT=sse

# OAuth2 Authentication (optional)
OAUTH_ENABLED=false
JWT_SECRET_KEY=your-secret-key
OAUTH_CLIENT_ID=wazuh-mcp-client
OAUTH_CLIENT_SECRET=your-client-secret

# Monitoring
ENABLE_METRICS=true
METRICS_PORT=9090

# Security
ENABLE_AUDIT_LOG=true
RATE_LIMIT_ENABLED=true
EOF
fi

echo "Configuration updated successfully!"
```

## Support

For migration support:
- [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- [Production Deployment Guide](docs/operations/PRODUCTION_DEPLOYMENT.md)
- [v3.0.0 Documentation](docs/v3/README_v3.md)
- [Troubleshooting Guides](docs/troubleshooting/)

## Next Steps

After successful migration:
1. Explore new remote MCP capabilities
2. Set up production monitoring
3. Configure security features
4. Optimize performance settings
5. Provide feedback on new features
6. Consider contributing to the project

This migration guide ensures a smooth transition while maintaining full compatibility with your existing setup and unlocking powerful new v3.0.0 features.