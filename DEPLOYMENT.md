# Production Deployment Guide - Wazuh MCP Server

This guide provides step-by-step instructions for deploying the production-ready Wazuh MCP Server using the unified FastMCP implementation.

## 🚀 Quick Deployment

### 1. Validate System Readiness

```bash
# Run the production validation script
python3 validate-production.py
```

This will check all requirements and provide a detailed report.

### 2. Install Dependencies

```bash
# Install all required dependencies
pip install -r requirements.txt
```

### 3. Configure Environment

```bash
# Copy the production template
cp .env.production .env

# Edit with your Wazuh credentials
nano .env
```

### 4. Test Server

```bash
# Test the server startup
./wazuh-mcp-server
```

### 5. Configure Claude Desktop

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "wazuh": {
      "command": "python3",
      "args": ["/full/path/to/Wazuh-MCP-Server/wazuh-mcp-server"]
    }
  }
}
```

## 📋 Detailed Installation

### System Requirements

- **Python**: 3.10 or higher
- **Memory**: 512MB minimum, 1GB recommended
- **Storage**: 200MB for installation
- **Network**: HTTPS access to Wazuh Manager
- **OS**: Linux, macOS, or Windows

### Dependencies Installation

The server requires these core dependencies:

```bash
# Core FastMCP framework
pip install fastmcp>=2.10.6

# HTTP client with HTTP/2 support
pip install "httpx[http2]>=0.27.0"

# MCP protocol support
pip install mcp>=1.10.1

# Utilities
pip install python-dateutil>=2.8.2 python-dotenv>=0.19.0

# Data validation
pip install "pydantic>=1.10.0,<3.0.0"

# Security
pip install pyjwt>=2.8.0 certifi>=2021.0.0

# System utilities
pip install packaging>=21.0 psutil>=5.9.0
```

Or install all at once:

```bash
pip install -r requirements.txt
```

### Configuration Setup

#### 1. Environment Variables

Create `.env` file from template:

```bash
cp .env.production .env
```

Essential configuration:

```bash
# Wazuh Server (Required)
WAZUH_HOST=your-wazuh-server.com
WAZUH_PORT=55000
WAZUH_USER=your-api-username
WAZUH_PASS=your-secure-password

# Security (Recommended)
VERIFY_SSL=true
LOG_LEVEL=INFO

# Performance
REQUEST_TIMEOUT_SECONDS=30
MAX_CONNECTIONS=10
```

#### 2. Wazuh API User Setup

Create a dedicated API user (don't use admin):

```bash
# On Wazuh Manager
curl -k -X POST "https://localhost:55000/security/users" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -d '{"username": "mcp-server", "password": "SecurePassword123!"}'

# Assign read-only permissions
curl -k -X POST "https://localhost:55000/security/users/mcp-server/roles?role_ids=1"
```

#### 3. SSL/TLS Configuration

For production with valid certificates:

```bash
VERIFY_SSL=true
SSL_TIMEOUT=30
```

For development/testing only:

```bash
VERIFY_SSL=false
ALLOW_SELF_SIGNED=true
```

## 🏭 Production Deployment Options

### Option 1: Direct Execution

```bash
# Simple production deployment
LOG_LEVEL=INFO ./wazuh-mcp-server
```

### Option 2: Process Manager (Recommended)

Using systemd on Linux:

```ini
# /etc/systemd/system/wazuh-mcp-server.service
[Unit]
Description=Wazuh MCP Server
After=network.target

[Service]
Type=simple
User=wazuh-mcp
WorkingDirectory=/opt/wazuh-mcp-server
ExecStart=/opt/wazuh-mcp-server/wazuh-mcp-server
Restart=always
RestartSec=10
Environment=LOG_LEVEL=INFO
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl enable wazuh-mcp-server
sudo systemctl start wazuh-mcp-server
sudo systemctl status wazuh-mcp-server
```

### Option 3: Docker Deployment

```dockerfile
# Dockerfile
FROM python:3.10-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY wazuh-mcp-server .
COPY .env .

RUN chmod +x wazuh-mcp-server

CMD ["./wazuh-mcp-server"]
```

Build and run:

```bash
docker build -t wazuh-mcp-server .
docker run -d --name wazuh-mcp -p 8000:8000 wazuh-mcp-server
```

## 🔐 Security Configuration

### 1. File Permissions

```bash
# Secure configuration files
chmod 600 .env
chmod 755 wazuh-mcp-server

# Secure the entire directory
chmod -R 755 src/
chmod -R 644 src/**/*.py
```

### 2. Network Security

- **Firewall**: Only allow necessary ports
- **SSL/TLS**: Always use SSL in production
- **Authentication**: Use strong, unique passwords
- **Network isolation**: Deploy in secure network segment

### 3. Monitoring

Enable comprehensive logging:

```bash
# Environment variables
LOG_LEVEL=INFO
STRUCTURED_LOGGING=true
ENABLE_METRICS=true

# Log to files (optional)
LOG_DIR=/var/log/wazuh-mcp-server
```

## 📊 Monitoring and Maintenance

### Health Checks

The server provides built-in health monitoring:

```bash
# Test server health (when running)
curl -X POST -H "Content-Type: application/json" \
  -d '{"method": "tools/call", "params": {"name": "get_server_health", "arguments": {}}}' \
  http://localhost:8000/mcp/v1/tools/call
```

### Log Monitoring

Monitor these log patterns:

```bash
# Critical errors
grep -i "critical\|error" /var/log/wazuh-mcp-server/wazuh-mcp.log

# Performance issues
grep -i "timeout\|slow" /var/log/wazuh-mcp-server/wazuh-mcp.log

# Authentication issues
grep -i "auth\|401\|403" /var/log/wazuh-mcp-server/security-audit.log
```

### Performance Tuning

Optimize for your environment:

```bash
# High-throughput environments
MAX_CONNECTIONS=50
POOL_SIZE=20
CACHE_TTL_SECONDS=600

# Low-resource environments
MAX_CONNECTIONS=5
POOL_SIZE=2
CACHE_TTL_SECONDS=60
```

## 🧪 Testing and Validation

### Pre-deployment Testing

```bash
# 1. Validate system readiness
python3 validate-production.py

# 2. Test configuration
python3 -c "from wazuh_mcp_server.config import WazuhConfig; print('Config OK')"

# 3. Test Wazuh connectivity
curl -k -X POST "https://your-wazuh-server:55000/security/user/authenticate" \
  -H "Content-Type: application/json" \
  -d '{"username":"your-user","password":"your-password"}'

# 4. Run test suite (if available)
python3 -m pytest tests/ -v
```

### Post-deployment Verification

```bash
# 1. Check server startup
tail -f /var/log/wazuh-mcp-server/wazuh-mcp.log

# 2. Test MCP functionality
./wazuh-mcp-server --test

# 3. Verify Claude Desktop integration
# (Restart Claude Desktop and check for Wazuh server in available tools)
```

## 🚨 Troubleshooting

### Common Issues

#### 1. Dependencies Missing

```bash
# Error: "No module named 'fastmcp'"
pip install fastmcp>=2.10.6

# Error: "No module named 'httpx'"
pip install "httpx[http2]>=0.27.0"
```

#### 2. Configuration Issues

```bash
# Error: "WAZUH_HOST must be provided"
# Fix: Set WAZUH_HOST in .env file

# Error: "Authentication failed"
# Fix: Verify WAZUH_USER and WAZUH_PASS
```

#### 3. SSL/TLS Issues

```bash
# Error: "SSL certificate verify failed"
# Development fix: VERIFY_SSL=false
# Production fix: Use valid certificates or custom CA bundle
```

#### 4. Performance Issues

```bash
# Slow responses
# Increase: REQUEST_TIMEOUT_SECONDS=60
# Increase: MAX_CONNECTIONS=20

# Memory issues
# Reduce: CACHE_TTL_SECONDS=60
# Reduce: MAX_ALERTS_PER_QUERY=500
```

### Debug Mode

Enable comprehensive debugging:

```bash
export DEBUG=true
export LOG_LEVEL=DEBUG
./wazuh-mcp-server 2>&1 | tee debug.log
```

### Logs Analysis

Key log files:

- `wazuh-mcp.log`: General operations
- `security-audit.log`: Security events
- `errors.log`: Error messages only

## 🔄 Updates and Maintenance

### Updating the Server

```bash
# 1. Backup current installation
cp -r /opt/wazuh-mcp-server /opt/wazuh-mcp-server.backup

# 2. Pull updates
git pull origin main

# 3. Update dependencies
pip install -r requirements.txt --upgrade

# 4. Validate
python3 validate-production.py

# 5. Restart service
sudo systemctl restart wazuh-mcp-server
```

### Regular Maintenance

- **Weekly**: Check logs for errors or warnings
- **Monthly**: Update dependencies for security patches
- **Quarterly**: Review and update configuration
- **Annually**: Rotate API credentials

## 📞 Support

### Getting Help

1. **Check validation**: `python3 validate-production.py`
2. **Review logs**: Check error and debug logs
3. **Test connectivity**: Verify Wazuh API access
4. **Check documentation**: README and inline comments

### Reporting Issues

Include this information:

- Output of `python3 validate-production.py`
- Relevant log entries (with sensitive data removed)
- Configuration (with credentials removed)
- Steps to reproduce the issue

---

## ✅ Production Checklist

Before going live:

- [ ] System validation passes (`python3 validate-production.py`)
- [ ] All dependencies installed
- [ ] Configuration file created and secured
- [ ] Wazuh API connectivity tested
- [ ] SSL/TLS properly configured
- [ ] Logging configured
- [ ] Process manager configured (systemd/supervisor)
- [ ] Health monitoring enabled
- [ ] Backup and recovery plan
- [ ] Security review completed
- [ ] Claude Desktop integration tested

**Your production-ready Wazuh MCP Server is now ready for deployment!**