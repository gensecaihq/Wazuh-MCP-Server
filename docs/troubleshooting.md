# Troubleshooting Guide

Comprehensive troubleshooting guide for common issues, debugging procedures, and performance optimization.

## Quick Diagnosis

### Production Readiness Check

```bash
# Run comprehensive system validation
python3 validate-production.py

# Quick health check
curl http://localhost:3000/health

# Test Wazuh connectivity
curl -k https://your-wazuh-server:55000/

# Check logs for errors
tail -n 100 logs/app.log | grep -E "(ERROR|CRITICAL)"
```

### System Status Overview

```bash
# Server health and metrics
curl http://localhost:3000/health | jq '.'

# Resource usage
docker stats wazuh-mcp-server  # For Docker deployment
ps aux | grep wazuh            # For manual deployment
free -h                        # Memory usage
df -h                          # Disk usage
```

## Common Issues

### Installation & Setup Issues

#### Python Version Incompatibility

**Problem:** `FastMCP requires Python 3.10+`

**Solutions:**
```bash
# Check current Python version
python3 --version

# Install Python 3.10+ on Ubuntu/Debian
sudo apt update
sudo apt install python3.10 python3.10-pip python3.10-venv

# Install on macOS with Homebrew
brew install python@3.10

# Install on RHEL/CentOS/Fedora
sudo dnf install python3.10 python3.10-pip

# Create virtual environment with specific Python version
python3.10 -m venv venv
source venv/bin/activate
```

#### Dependency Installation Failures

**Problem:** `pip install` fails with compilation errors

**Solutions:**
```bash
# Install system dependencies (Ubuntu/Debian)
sudo apt install build-essential python3-dev libffi-dev libssl-dev

# Install system dependencies (RHEL/CentOS/Fedora)
sudo dnf groupinstall "Development Tools"
sudo dnf install python3-devel libffi-devel openssl-devel

# Install system dependencies (macOS)
xcode-select --install
brew install libffi openssl

# Update pip and install with no cache
pip install --upgrade pip
pip install --no-cache-dir -r requirements.txt

# Install with specific versions
pip install fastmcp>=2.10.6 httpx>=0.27.0 --force-reinstall
```

#### Permission Issues

**Problem:** Permission denied errors during installation or execution

**Solutions:**
```bash
# Fix file permissions
chmod +x wazuh-mcp-server
chmod 600 .env
chown -R $(whoami):$(whoami) .

# Create logs directory with proper permissions
mkdir -p logs
chmod 755 logs

# For Docker deployment
sudo chown -R 1000:1000 logs/
```

### Configuration Issues

#### Invalid Configuration Values

**Problem:** Configuration validation errors

**Diagnosis:**
```bash
# Test configuration loading
python3 -c "
from src.wazuh_mcp_server.config import WazuhConfig
try:
    config = WazuhConfig.from_env()
    print('✅ Configuration valid')
except Exception as e:
    print(f'❌ Configuration error: {e}')
"
```

**Solutions:**
```bash
# Check environment variables
printenv | grep WAZUH

# Validate required fields
if [ -z "$WAZUH_HOST" ]; then echo "❌ WAZUH_HOST not set"; fi
if [ -z "$WAZUH_USER" ]; then echo "❌ WAZUH_USER not set"; fi
if [ -z "$WAZUH_PASS" ]; then echo "❌ WAZUH_PASS not set"; fi

# Check .env file format
cat .env | grep -v '^#' | grep '='

# Validate password requirements
python3 -c "
password = input('Enter password: ')
if len(password) < 12:
    print('❌ Password too short (min 12 chars)')
if not any(c.isupper() for c in password):
    print('❌ Password needs uppercase letter')
if not any(c.islower() for c in password):
    print('❌ Password needs lowercase letter')
if not any(c.isdigit() for c in password):
    print('❌ Password needs number')
if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
    print('❌ Password needs special character')
"
```

#### SSL/TLS Certificate Issues

**Problem:** SSL certificate verification failures

**Diagnosis:**
```bash
# Test SSL connection
openssl s_client -connect $WAZUH_HOST:55000 -servername $WAZUH_HOST

# Check certificate details
echo | openssl s_client -connect $WAZUH_HOST:55000 2>/dev/null | \
openssl x509 -noout -dates -subject -issuer

# Test with curl
curl -v -k https://$WAZUH_HOST:55000/
```

**Solutions:**
```bash
# For development/testing (NOT recommended for production)
export VERIFY_SSL=false
export ALLOW_SELF_SIGNED=true

# For production - add custom CA certificate
export CA_BUNDLE_PATH=/path/to/custom-ca.pem

# Download and trust certificate
echo -n | openssl s_client -connect $WAZUH_HOST:55000 | \
sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > wazuh-ca.crt

# Add to system trust store (Ubuntu/Debian)
sudo cp wazuh-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# Add to Python requests
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
```

### Connectivity Issues

#### Wazuh API Connection Failures

**Problem:** Cannot connect to Wazuh API

**Diagnosis:**
```bash
# Test network connectivity
ping $WAZUH_HOST
nc -zv $WAZUH_HOST 55000
telnet $WAZUH_HOST 55000

# Test HTTP connectivity
curl -I -k https://$WAZUH_HOST:55000/

# Test API authentication
curl -k -X POST "https://$WAZUH_HOST:55000/security/user/authenticate" \
  -H "Content-Type: application/json" \
  -d "{\"username\":\"$WAZUH_USER\",\"password\":\"$WAZUH_PASS\"}"
```

**Solutions:**
```bash
# Check firewall rules
sudo ufw status          # Ubuntu/Debian
sudo firewall-cmd --list-all  # RHEL/CentOS/Fedora
sudo iptables -L         # Generic Linux

# Check network routes
traceroute $WAZUH_HOST
mtr $WAZUH_HOST

# DNS resolution
nslookup $WAZUH_HOST
dig $WAZUH_HOST

# Proxy configuration (if applicable)
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1,.local
```

#### Rate Limiting Issues

**Problem:** Too many requests / Rate limit exceeded

**Diagnosis:**
```bash
# Check rate limit status
curl -I http://localhost:3000/health

# Monitor rate limit headers
curl -v http://localhost:3000/health 2>&1 | grep -i rate

# Check logs for rate limit violations
grep "rate limit" logs/app.log
```

**Solutions:**
```bash
# Adjust rate limiting configuration
export MAX_REQUESTS_PER_MINUTE=120
export BURST_SIZE=20

# Implement client-side rate limiting
sleep 1  # Add delays between requests

# Use connection pooling
# Configure HTTP client to reuse connections
```

### Performance Issues

#### Slow Response Times

**Problem:** API responses are slow

**Diagnosis:**
```bash
# Measure response times
time curl http://localhost:3000/health

# Detailed timing with curl
curl -w "@curl-format.txt" http://localhost:3000/health

# Create curl-format.txt
cat > curl-format.txt << 'EOF'
     time_namelookup:  %{time_namelookup}\n
        time_connect:  %{time_connect}\n
     time_appconnect:  %{time_appconnect}\n
    time_pretransfer:  %{time_pretransfer}\n
       time_redirect:  %{time_redirect}\n
  time_starttransfer:  %{time_starttransfer}\n
                     ----------\n
          time_total:  %{time_total}\n
EOF

# Monitor system resources
top -p $(pgrep -f wazuh-mcp-server)
iostat 1 5
vmstat 1 5
```

**Solutions:**
```bash
# Optimize configuration
export MAX_CONNECTIONS=20
export POOL_SIZE=10
export CACHE_TTL_SECONDS=300
export REQUEST_TIMEOUT_SECONDS=30

# Enable HTTP/2
export ENABLE_HTTP2=true

# Optimize Python settings
export PYTHONOPTIMIZE=1
export PYTHONDONTWRITEBYTECODE=1

# Increase system limits
ulimit -n 4096  # File descriptors
```

#### Memory Issues

**Problem:** High memory usage or memory leaks

**Diagnosis:**
```bash
# Monitor memory usage
ps aux --sort=-%mem | head -10
free -h
cat /proc/meminfo

# Python memory profiling
python3 -m memory_profiler script.py

# For Docker containers
docker stats wazuh-mcp-server
docker exec wazuh-mcp-server free -h
```

**Solutions:**
```bash
# Optimize memory settings
export PYTHON_GC_THRESHOLD=700,10,10
export MALLOC_TRIM_THRESHOLD=65536

# Limit alert processing
export MAX_ALERTS_PER_QUERY=500

# Enable aggressive garbage collection
export CACHE_CLEANUP_AGGRESSIVE=true

# Restart service periodically (for production)
# Add to crontab: 0 2 * * * systemctl restart wazuh-mcp-server
```

### Authentication Issues

#### JWT Token Problems

**Problem:** Authentication failures with JWT tokens

**Diagnosis:**
```bash
# Check JWT configuration
echo $JWT_SECRET_KEY | wc -c  # Should be 32+ characters

# Test token generation
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"password"}'

# Decode JWT token (for debugging)
jwt_token="your-jwt-token-here"
echo $jwt_token | cut -d. -f2 | base64 -d | jq '.'
```

**Solutions:**
```bash
# Generate new JWT secret
export JWT_SECRET_KEY=$(openssl rand -base64 32)

# Check token expiry
export TOKEN_EXPIRY_MINUTES=30

# Clear token cache
rm -rf ~/.cache/wazuh-mcp-tokens

# Reset authentication
curl -X POST http://localhost:3000/auth/logout
```

#### Account Lockout Issues

**Problem:** Account locked due to failed attempts

**Diagnosis:**
```bash
# Check lockout status
grep "account locked" logs/audit.log

# Check failed login attempts
grep "login_failure" logs/audit.log | tail -10
```

**Solutions:**
```bash
# Wait for lockout to expire (default 15 minutes)
# Or reset lockout manually

# Adjust lockout settings
export MAX_LOGIN_ATTEMPTS=10
export LOCKOUT_DURATION_MINUTES=5

# Reset user account
# (Implementation depends on authentication backend)
```

### Docker-Specific Issues

#### Container Won't Start

**Problem:** Docker container fails to start

**Diagnosis:**
```bash
# Check container logs
docker logs wazuh-mcp-server

# Check container status
docker ps -a
docker inspect wazuh-mcp-server

# Check Docker daemon logs
sudo journalctl -u docker.service
```

**Solutions:**
```bash
# Rebuild container
docker compose down
docker compose build --no-cache
docker compose up -d

# Check resource limits
docker system df
docker system prune

# Fix permission issues
sudo chown -R 1000:1000 logs/
chmod 755 wazuh-mcp-server
```

#### Container Health Check Failures

**Problem:** Health checks failing

**Diagnosis:**
```bash
# Manual health check
docker exec wazuh-mcp-server curl -f http://localhost:3000/health

# Check health check logs
docker inspect wazuh-mcp-server | jq '.[0].State.Health'

# Run validation inside container
docker exec wazuh-mcp-server python3 validate-production.py
```

**Solutions:**
```bash
# Increase health check timeouts
# In docker-compose.yml:
healthcheck:
  interval: 60s
  timeout: 30s
  retries: 5
  start_period: 60s

# Fix health check command
docker exec wazuh-mcp-server python3 -c "
import sys
sys.path.insert(0, '/app/src')
from wazuh_mcp_server.config import WazuhConfig
WazuhConfig.from_env()
print('Health check passed')
"
```

### Claude Desktop Integration Issues

#### MCP Server Not Recognized

**Problem:** Claude Desktop doesn't recognize the MCP server

**Diagnosis:**
```bash
# Check Claude Desktop config file location
# macOS: ~/.config/claude/claude_desktop_config.json
# Windows: %APPDATA%/Claude/claude_desktop_config.json

# Validate JSON syntax
cat ~/.config/claude/claude_desktop_config.json | jq '.'

# Check file permissions
ls -la ~/.config/claude/claude_desktop_config.json
```

**Solutions:**
```bash
# Fix JSON syntax
{
  "mcpServers": {
    "wazuh": {
      "command": "python3",
      "args": ["/full/path/to/Wazuh-MCP-Server/wazuh-mcp-server", "--stdio"]
    }
  }
}

# Use absolute paths
which python3  # Use full path
pwd            # Get full path to project

# Test server manually
echo '{"method": "initialize", "params": {}}' | ./wazuh-mcp-server --stdio

# Restart Claude Desktop after config changes
```

#### STDIO Communication Issues

**Problem:** STDIO transport not working

**Diagnosis:**
```bash
# Test STDIO communication
echo '{"jsonrpc": "2.0", "method": "initialize", "params": {}, "id": 1}' | \
./wazuh-mcp-server --stdio

# Check for output buffering issues
stdbuf -oL ./wazuh-mcp-server --stdio

# Test with timeout
timeout 10 ./wazuh-mcp-server --stdio
```

**Solutions:**
```bash
# Fix buffering issues
export PYTHONUNBUFFERED=1

# Use line buffering
python3 -u wazuh-mcp-server --stdio

# Add flush calls in code
import sys
sys.stdout.flush()
sys.stderr.flush()
```

## Debugging Procedures

### Enable Debug Logging

```bash
# Set debug environment
export LOG_LEVEL=DEBUG
export ENABLE_DEBUG_LOGGING=true

# Restart server with debug
./wazuh-mcp-server --debug --verbose

# Monitor debug logs
tail -f logs/debug.log | jq '.'

# Filter specific components
tail -f logs/debug.log | grep "wazuh_api"
tail -f logs/debug.log | grep "rate_limit"
```

### Interactive Debugging

```bash
# Start Python debugger
python3 -m pdb src/wazuh_mcp_server/server.py

# Use iPython for interactive debugging
pip install ipython
ipython
>>> from src.wazuh_mcp_server.server import *
>>> # Test components interactively

# Step-by-step component testing
python3 -c "
from src.wazuh_mcp_server.config import WazuhConfig
config = WazuhConfig.from_env()
print('✅ Config loaded')

from src.wazuh_mcp_server.server import get_http_client
import asyncio
client = asyncio.run(get_http_client())
print('✅ HTTP client created')
"
```

### Performance Profiling

```bash
# CPU profiling
python3 -m cProfile -o profile.stats src/wazuh_mcp_server/server.py

# Analyze profile
python3 -c "
import pstats
p = pstats.Stats('profile.stats')
p.sort_stats('cumulative').print_stats(10)
"

# Memory profiling
pip install memory-profiler
python3 -m memory_profiler src/wazuh_mcp_server/server.py

# Line-by-line profiling
pip install line-profiler
kernprof -l -v src/wazuh_mcp_server/server.py
```

### Network Debugging

```bash
# Monitor network traffic
sudo tcpdump -i any port 55000 -A

# HTTP debugging with mitmproxy
pip install mitmproxy
mitmdump -p 8080 --set confdir=~/.mitmproxy

# Configure proxy
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080

# SSL debugging
openssl s_client -debug -connect $WAZUH_HOST:55000

# DNS debugging
dig +trace $WAZUH_HOST
nslookup -debug $WAZUH_HOST
```

## Performance Optimization

### System Optimization

```bash
# Increase file descriptor limits
echo "* soft nofile 4096" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 8192" | sudo tee -a /etc/security/limits.conf

# Optimize TCP settings
echo 'net.core.somaxconn = 1024' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_keepalive_time = 600' | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

# Optimize Python
export PYTHONOPTIMIZE=1
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=random
```

### Application Optimization

```bash
# Connection pooling
export MAX_CONNECTIONS=20
export POOL_SIZE=10
export KEEPALIVE_EXPIRY=30

# Caching
export CACHE_TTL_SECONDS=300
export ENABLE_CACHING=true

# Request optimization
export REQUEST_TIMEOUT_SECONDS=30
export MAX_ALERTS_PER_QUERY=1000

# Memory management
export CACHE_CLEANUP_AGGRESSIVE=true
export MEMORY_CHECK_INTERVAL=300
```

## Log Analysis

### Log Locations

```bash
# Application logs
tail -f logs/app.log

# Audit logs
tail -f logs/audit.log

# Debug logs
tail -f logs/debug.log

# Error logs
tail -f logs/error.log

# Docker logs
docker logs --follow wazuh-mcp-server
```

### Log Analysis Commands

```bash
# Error analysis
grep -E "(ERROR|CRITICAL)" logs/app.log | tail -20

# Performance analysis
grep "response_time" logs/app.log | awk '{print $7}' | sort -n

# Security analysis
grep "authentication" logs/audit.log
grep "rate_limit" logs/audit.log

# JSON log parsing
cat logs/app.log | jq 'select(.level=="ERROR")'

# Real-time monitoring
tail -f logs/app.log | grep --line-buffered "ERROR"
```

### Log Rotation

```bash
# Configure logrotate
sudo tee /etc/logrotate.d/wazuh-mcp << 'EOF'
/path/to/Wazuh-MCP-Server/logs/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF

# Manual log rotation
sudo logrotate -f /etc/logrotate.d/wazuh-mcp
```

## Getting Help

### Support Channels

1. **Documentation**: Check [docs/](../docs/) directory
2. **GitHub Issues**: [Create an issue](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
3. **GitHub Discussions**: [Join discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)
4. **Security Issues**: Email security@gensecai.com

### Information to Include

When seeking help, include:

```bash
# System information
uname -a
python3 --version
docker --version
pip freeze | grep -E "(fastmcp|httpx|mcp)"

# Configuration (sanitized)
cat .env | sed 's/PASS=.*/PASS=***REDACTED***/'

# Recent logs
tail -50 logs/app.log

# Error details
python3 validate-production.py 2>&1

# Network connectivity
curl -I -k https://$WAZUH_HOST:55000/ 2>&1
```

### Diagnostic Script

```bash
#!/bin/bash
# diagnostic.sh - Collect diagnostic information

echo "=== Wazuh MCP Server Diagnostic ==="
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo

echo "=== System Information ==="
uname -a
python3 --version
docker --version 2>/dev/null || echo "Docker not installed"
echo

echo "=== Configuration Check ==="
python3 validate-production.py 2>&1
echo

echo "=== Connectivity Test ==="
if [ -n "$WAZUH_HOST" ]; then
    ping -c 3 $WAZUH_HOST 2>/dev/null || echo "Ping failed"
    nc -zv $WAZUH_HOST 55000 2>&1 || echo "Port 55000 not accessible"
    curl -I -k --max-time 10 https://$WAZUH_HOST:55000/ 2>&1 || echo "HTTPS connection failed"
else
    echo "WAZUH_HOST not set"
fi
echo

echo "=== Recent Errors ==="
if [ -f logs/app.log ]; then
    grep -E "(ERROR|CRITICAL)" logs/app.log | tail -10
else
    echo "No log file found"
fi
echo

echo "=== Resource Usage ==="
free -h
df -h .
ps aux | grep -E "(python|wazuh)" | grep -v grep
echo

echo "=== Network Status ==="
netstat -tuln | grep -E ":(3000|55000)"
```

For additional troubleshooting resources:
- [Security Troubleshooting](security-troubleshooting.md)
- [Docker Troubleshooting](docker-troubleshooting.md)
- [Performance Tuning](performance-tuning.md)
- [Network Debugging](network-debugging.md)