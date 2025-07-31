# 🔧 Configuration Guide

**Complete guide to configuring your Wazuh MCP Server for any environment.**

## ⚡ Quick Start

**Fastest way to configure:**
```bash
./configure-wazuh.sh
```

The interactive script handles everything automatically.

## 📋 Configuration Overview

The server uses **two configuration methods**:
1. **`.env.wazuh`** - Main configuration (created by configure script)
2. **Environment variables** - For Docker override

## 🎯 Required Settings

**Only 3 settings are required:**

```env
WAZUH_HOST=your-wazuh-manager.com    # Your Wazuh Manager hostname/IP
WAZUH_USER=your-api-username         # API user with read permissions  
WAZUH_PASS=your-api-password         # API password
```

**That's it!** Everything else has sensible defaults.

## 🔧 Configuration Methods

### Method 1: Interactive Script (Recommended)

```bash
./configure-wazuh.sh
```

**Advantages:**
- ✅ Validates your settings
- ✅ Tests Wazuh connectivity  
- ✅ Starts server automatically
- ✅ No manual file editing

### Method 2: Manual Configuration

1. **Copy template:**
   ```bash
   cp config/wazuh.env.example .env.wazuh
   ```

2. **Edit settings:**
   ```bash
   nano .env.wazuh
   ```

3. **Start server:**
   ```bash
   docker compose up -d
   ```

### Method 3: Environment Variables

**Override any setting:**
```bash
export WAZUH_HOST=my-wazuh.com
export MCP_PORT=4000
docker compose up -d
```

## 🚀 Transport Modes

### HTTP Mode (Default)
**Best for:** Web clients, REST APIs, remote access

```env
MCP_TRANSPORT=http
MCP_HOST=0.0.0.0  
MCP_PORT=3000
```

**Access:** `http://localhost:3000`

### STDIO Mode
**Best for:** Claude Desktop direct integration

```env
MCP_TRANSPORT=stdio
```

**Claude Desktop config:**
```json
{
  "mcpServers": {
    "wazuh": {
      "command": "docker",
      "args": ["compose", "exec", "wazuh-mcp-server", "./wazuh-mcp-server", "--stdio"],
      "cwd": "/path/to/Wazuh-MCP-Server"
    }
  }
}
```

## ⚙️ Optional Settings

### Wazuh Connection
```env
WAZUH_PORT=55000              # Default: 55000
VERIFY_SSL=true               # Default: true (recommended)
```

### Performance Tuning
```env
MAX_ALERTS_PER_QUERY=1000     # Max alerts per request
REQUEST_TIMEOUT_SECONDS=30    # API timeout
MAX_CONNECTIONS=10            # Connection pool
```

### Indexer (Enhanced Features)
```env
# Enable only if you have Wazuh Indexer
WAZUH_INDEXER_HOST=indexer.com
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=password
WAZUH_INDEXER_PORT=9200
```

### Logging
```env
LOG_LEVEL=INFO                # DEBUG, INFO, WARNING, ERROR
STRUCTURED_LOGGING=true       # JSON log format
```

## ✅ Validation & Testing

### Test Your Configuration

```bash
# Validate Docker config
docker compose config

# Test server health
curl http://localhost:3000/health

# Run comprehensive tests
docker compose exec wazuh-mcp-server python3 test-functionality.py

# Test Wazuh connectivity
docker compose exec wazuh-mcp-server python3 test-wazuh-connectivity.py
```

### Check Server Status

```bash
# Container status
docker compose ps

# Real-time logs
docker compose logs -f

# Error checking
docker compose logs | grep -i error
```

## 🚨 Troubleshooting

### Connection Issues

**Problem:** Can't connect to Wazuh Manager
```bash
# Test connectivity
docker compose exec wazuh-mcp-server curl -k https://YOUR_WAZUH_HOST:55000

# Check firewall
telnet YOUR_WAZUH_HOST 55000
```

**Solutions:**
- ✅ Verify `WAZUH_HOST` is correct
- ✅ Check firewall allows port 55000
- ✅ Confirm Wazuh API service is running

### Authentication Issues

**Problem:** Invalid credentials
```bash
# Test authentication
curl -k "https://WAZUH_HOST:55000/security/user/authenticate" \
  -u "USERNAME:PASSWORD"
```

**Solutions:**
- ✅ Verify username/password in Wazuh
- ✅ Check API user permissions
- ✅ Ensure no special characters break parsing

### SSL Certificate Issues

**Problem:** SSL verification fails
```bash
# Disable SSL verification (development only)
echo "VERIFY_SSL=false" >> .env.wazuh
docker compose restart
```

**Solutions:**
- ✅ Use `VERIFY_SSL=false` for self-signed certs
- ✅ Install proper certificates
- ✅ Update certificate bundle

### Container Issues

**Problem:** Container won't start
```bash
# Check container health
docker compose ps
docker compose logs wazuh-mcp-server

# Check port conflicts
lsof -i :3000
```

**Solutions:**
- ✅ Check Docker daemon is running
- ✅ Verify port 3000 is available
- ✅ Review error logs

## 🔒 Security Best Practices

### File Permissions
```bash
# Protect configuration file
chmod 600 .env.wazuh
```

### Strong Authentication
- ✅ Use dedicated Wazuh API user
- ✅ Minimum 12-character passwords
- ✅ Rotate credentials regularly
- ✅ Limit API user permissions

### Network Security
- ✅ Enable SSL verification in production
- ✅ Use firewall rules
- ✅ Restrict network access
- ✅ Monitor API access logs

## 🌍 Environment-Specific Configs

### Development
```env
VERIFY_SSL=false
LOG_LEVEL=DEBUG
MAX_ALERTS_PER_QUERY=10
```

### Staging
```env
VERIFY_SSL=true
LOG_LEVEL=INFO
MAX_ALERTS_PER_QUERY=100
```

### Production
```env
VERIFY_SSL=true
LOG_LEVEL=WARNING
MAX_ALERTS_PER_QUERY=1000
STRUCTURED_LOGGING=true
```

## 📊 Configuration Examples

### Basic Setup
```env
WAZUH_HOST=wazuh.company.com
WAZUH_USER=mcp-reader
WAZUH_PASS=SecurePassword123
```

### High-Performance Setup
```env
WAZUH_HOST=wazuh.company.com
WAZUH_USER=mcp-reader
WAZUH_PASS=SecurePassword123
MAX_ALERTS_PER_QUERY=5000
MAX_CONNECTIONS=20
REQUEST_TIMEOUT_SECONDS=60
```

### Multi-Node Wazuh
```env
WAZUH_HOST=wazuh-manager.company.com
WAZUH_INDEXER_HOST=wazuh-indexer.company.com
WAZUH_USER=mcp-reader
WAZUH_PASS=SecurePassword123
```

## 🔄 Configuration Updates

### Updating Settings
```bash
# Edit configuration
nano .env.wazuh

# Apply changes
docker compose restart

# Verify
curl http://localhost:3000/health
```

### Reconfiguration
```bash
# Re-run configuration wizard
./configure-wazuh.sh

# Or manually update and restart
docker compose down
docker compose up -d
```

## 📚 Advanced Topics

### Custom Docker Override
Create `docker-compose.override.yml`:
```yaml
services:
  wazuh-mcp-server:
    environment:
      - LOG_LEVEL=DEBUG
    ports:
      - "4000:3000"
```

### Environment File Priority
1. Environment variables (highest)
2. `.env.wazuh` 
3. Container defaults (lowest)

### Configuration Validation
The server validates all settings on startup and provides detailed error messages for invalid configurations.