# Configuration Guide

## Overview

Wazuh MCP Server uses a single configuration file `config/wazuh.env` for all settings. This guide covers all configuration options.

> **Note**: This project uses `compose.yml` following modern Docker Compose V2+ standards. All commands use `docker compose` (not `docker-compose`).

## Quick Setup

```bash
# Run the configuration wizard
./scripts/configure.sh
```

## Configuration File

All settings are stored in `config/wazuh.env`:

### Required Settings

```env
# Wazuh Manager Connection
WAZUH_HOST=your-wazuh-manager.com    # Hostname or IP address
WAZUH_USER=your-api-username         # API user with read permissions
WAZUH_PASS=your-api-password         # API password
```

### Optional Settings

#### Basic Options

```env
# Wazuh Manager Port (default: 55000)
WAZUH_PORT=55000

# SSL Certificate Verification (default: true)
# Set to false for self-signed certificates
VERIFY_SSL=true
```

#### Wazuh Indexer (Enhanced Features)

If you have Wazuh Indexer installed, enable these for enhanced analytics:

```env
# Indexer Connection
WAZUH_INDEXER_HOST=your-wazuh-indexer.com
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=your-indexer-password
WAZUH_INDEXER_PORT=9200
```

#### Transport Mode

```env
# MCP Transport Mode (default: stdio)
# - stdio: For Claude Desktop integration
# - http: For remote/web access
MCP_TRANSPORT=stdio

# HTTP Mode Settings (only used when MCP_TRANSPORT=http)
MCP_HOST=0.0.0.0
MCP_PORT=3000
```

#### Advanced Settings

These rarely need to be changed:

```env
# Performance Tuning
MAX_ALERTS_PER_QUERY=1000      # Max alerts per API request
REQUEST_TIMEOUT_SECONDS=30     # API request timeout
MAX_CONNECTIONS=10             # Connection pool size

# Logging
LOG_LEVEL=INFO                 # DEBUG, INFO, WARNING, ERROR
```

## Configuration Methods

### Method 1: Configuration Wizard (Recommended)

```bash
./scripts/configure.sh
```

Interactive wizard that guides you through all settings.

### Method 2: Copy Template

```bash
cp config/wazuh.env.example config/wazuh.env
nano config/wazuh.env
```

### Method 3: Environment Variables

You can override any setting with environment variables:

```bash
export WAZUH_HOST=my-wazuh.com
docker compose up -d
```

## Transport Modes

### STDIO Mode (Default)

Best for Claude Desktop integration:
- Direct communication
- No network configuration
- Lowest latency

### HTTP Mode

For remote access or web clients:
1. Set in configuration:
   ```bash
   echo "MCP_TRANSPORT=http" >> config/wazuh.env
   ```

2. Restart server:
   ```bash
   docker compose restart
   ```

3. Access at `http://localhost:3000`

## Validation

### Test Configuration

```bash
# Validate configuration syntax
docker compose config

# Test Wazuh connection
python3 tools/test-functionality.py
```

### Check Logs

```bash
# View server logs
docker compose logs -f

# Check for configuration errors
docker compose logs | grep -i error
```

## Troubleshooting

### Common Issues

1. **Connection Failed**
   - Check WAZUH_HOST is reachable
   - Verify firewall allows port 55000
   - Test with: `curl -k https://${WAZUH_HOST}:55000`

2. **Authentication Failed**
   - Verify API user exists in Wazuh
   - Check user has read permissions
   - Ensure password doesn't contain special shell characters

3. **SSL Errors**
   - Set `VERIFY_SSL=false` for self-signed certificates
   - Or add certificate to trusted store

### Debug Mode

Enable debug logging:
```bash
echo "LOG_LEVEL=DEBUG" >> config/wazuh.env
docker compose restart
```

## Security Best Practices

1. **Protect Configuration File**
   ```bash
   chmod 600 config/wazuh.env
   ```

2. **Use Strong Passwords**
   - Minimum 12 characters
   - Mix of letters, numbers, symbols

3. **Enable SSL Verification**
   - Keep `VERIFY_SSL=true` in production
   - Use proper certificates

4. **Restrict Network Access**
   - Use firewall rules
   - Limit API user permissions in Wazuh

## Migration from Previous Versions

If upgrading from an older version:

1. Backup existing configuration
2. Run configuration wizard: `./scripts/configure.sh`
3. The wizard will migrate your settings automatically

## Environment-Specific Configurations

### Development
```env
VERIFY_SSL=false
LOG_LEVEL=DEBUG
```

### Production
```env
VERIFY_SSL=true
LOG_LEVEL=INFO
```

### Testing
```env
MAX_ALERTS_PER_QUERY=10
REQUEST_TIMEOUT_SECONDS=5
```