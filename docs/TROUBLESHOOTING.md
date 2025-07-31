# 🚨 Troubleshooting Guide

**Quick solutions to common issues with Wazuh MCP Server.**

## 🔍 Quick Diagnostics

**Run these commands first to identify issues:**

```bash
# 1. Check container status
docker compose ps

# 2. View recent logs
docker compose logs --tail=50 wazuh-mcp-server

# 3. Test server health
curl http://localhost:3000/health

# 4. Run comprehensive diagnostics
docker compose exec wazuh-mcp-server python3 validate-production.py
```

## 🐳 Container Issues

### Container Won't Start

**Symptoms:**
- Container shows "Exited" status
- `docker compose up` returns immediately
- No server response at port 3000

**Diagnosis:**
```bash
# Check container logs
docker compose logs wazuh-mcp-server

# Validate Docker configuration
docker compose config

# Check if port is available
lsof -i :3000
netstat -tulpn | grep :3000
```

**Solutions:**

1. **Configuration Error:**
   ```bash
   # Re-run configuration wizard
   ./configure-wazuh.sh
   
   # Or check .env.wazuh file exists
   ls -la .env.wazuh
   ```

2. **Port Conflict:**
   ```bash
   # Use different port
   echo "MCP_PORT=3001" >> .env.wazuh
   docker compose up -d
   ```

3. **Docker Issues:**
   ```bash
   # Restart Docker daemon
   sudo systemctl restart docker  # Linux
   # Or restart Docker Desktop on Mac/Windows
   
   # Remove containers and rebuild
   docker compose down --volumes
   docker compose up -d --build
   ```

### Container Starts But Exits Immediately

**Symptoms:**
- Container starts then immediately exits
- Logs show configuration errors

**Diagnosis:**
```bash
# Check detailed startup logs
docker compose logs -f wazuh-mcp-server

# Run container interactively for debugging
docker compose run --rm wazuh-mcp-server bash
```

**Solutions:**

1. **Missing Environment File:**
   ```bash
   # Ensure .env.wazuh exists
   cp config/wazuh.env.example .env.wazuh
   # Edit with your settings and restart
   ```

2. **Invalid Configuration:**
   ```bash
   # Validate configuration syntax
   docker compose exec wazuh-mcp-server python3 -c "
   from src.wazuh_mcp_server.config import WazuhConfig
   config = WazuhConfig.from_env()
   print('Configuration loaded successfully')
   "
   ```

## 🔐 Connection Issues

### Cannot Connect to Wazuh Manager

**Symptoms:**
- "Connection refused" errors
- "Name resolution failed" errors
- Server starts but tools fail

**Diagnosis:**
```bash
# Test basic connectivity
docker compose exec wazuh-mcp-server ping your-wazuh-host

# Test Wazuh API port
docker compose exec wazuh-mcp-server curl -k https://your-wazuh-host:55000

# Check DNS resolution
docker compose exec wazuh-mcp-server nslookup your-wazuh-host
```

**Solutions:**

1. **Hostname/IP Issues:**
   ```bash
   # Use IP address instead of hostname
   echo "WAZUH_HOST=192.168.1.100" >> .env.wazuh
   docker compose restart
   ```

2. **Network Connectivity:**
   ```bash
   # Check firewall rules
   telnet your-wazuh-host 55000
   
   # Test from host machine
   curl -k https://your-wazuh-host:55000
   ```

3. **Docker Network Issues:**
   ```bash
   # Restart with host networking (temporary debugging)
   docker run --rm --net=host -it python:3.12-slim curl -k https://your-wazuh-host:55000
   ```

### Authentication Failed

**Symptoms:**
- "401 Unauthorized" errors
- "Invalid credentials" messages
- Tools return authentication errors

**Diagnosis:**
```bash
# Test credentials directly
curl -k "https://your-wazuh-host:55000/security/user/authenticate" \
  -u "your-username:your-password"

# Check configuration
docker compose exec wazuh-mcp-server python3 -c "
import os
print(f'WAZUH_HOST: {os.getenv(\"WAZUH_HOST\")}')
print(f'WAZUH_USER: {os.getenv(\"WAZUH_USER\")}')
print('WAZUH_PASS: [HIDDEN]')
"
```

**Solutions:**

1. **Verify Credentials:**
   - Log into Wazuh dashboard with same credentials
   - Check user exists in Wazuh: Security → Users
   - Verify user has API permissions

2. **Fix Special Characters:**
   ```bash
   # Escape special characters in password
   # Or use single quotes in .env.wazuh file
   WAZUH_PASS='password@123!'
   ```

3. **User Permissions:**
   - Ensure user has at least `read` permissions
   - Check user is not locked/expired

## 🌐 Network & Port Issues

### Port 3000 Access Issues

**Symptoms:**
- Cannot access http://localhost:3000
- Connection timeouts
- Server appears running but not reachable

**Diagnosis:**
```bash
# Check port binding
docker compose ps
ss -tulpn | grep :3000

# Test from inside container
docker compose exec wazuh-mcp-server curl http://localhost:3000/health

# Check firewall
sudo ufw status  # Ubuntu
sudo firewall-cmd --list-ports  # RHEL/CentOS
```

**Solutions:**

1. **Port Binding:**
   ```bash
   # Check compose.yml port mapping
   grep -A 5 "ports:" compose.yml
   
   # Use different port
   echo "MCP_PORT=3001" >> .env.wazuh
   docker compose up -d
   ```

2. **Firewall Issues:**
   ```bash
   # Allow port through firewall
   sudo ufw allow 3000  # Ubuntu
   sudo firewall-cmd --permanent --add-port=3000/tcp  # RHEL/CentOS
   ```

### Claude Desktop Connection Issues

**Symptoms:**
- Claude Desktop can't find MCP server
- STDIO mode errors
- MCP server not responding to Claude

**Diagnosis:**
```bash
# Verify STDIO mode
grep MCP_TRANSPORT .env.wazuh

# Test STDIO mode manually
echo '{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}' | \
  docker compose exec -T wazuh-mcp-server ./wazuh-mcp-server --stdio
```

**Solutions:**

1. **Enable STDIO Mode:**
   ```bash
   echo "MCP_TRANSPORT=stdio" >> .env.wazuh
   docker compose restart
   ```

2. **Claude Desktop Configuration:**
   ```json
   {
     "mcpServers": {
       "wazuh": {
         "command": "docker",
         "args": ["compose", "exec", "wazuh-mcp-server", "./wazuh-mcp-server", "--stdio"],
         "cwd": "/absolute/path/to/Wazuh-MCP-Server"
       }
     }
   }
   ```

3. **Path Issues:**
   - Use absolute path in `cwd`
   - Ensure Docker is in PATH for Claude Desktop
   - Check Claude Desktop logs for errors

## 📊 Performance Issues

### Slow Response Times

**Symptoms:**
- API calls take > 30 seconds
- Timeouts on large queries
- High CPU/memory usage

**Diagnosis:**
```bash
# Check resource usage
docker stats wazuh-mcp-server

# Monitor response times
time curl http://localhost:3000/health

# Check Wazuh server load
docker compose exec wazuh-mcp-server python3 -c "
import time
import asyncio
from src.wazuh_mcp_server.api.wazuh_client import WazuhClient
from src.wazuh_mcp_server.config import WazuhConfig

async def test():
    config = WazuhConfig.from_env()
    client = WazuhClient(config)
    start = time.time()
    result = await client.get_alerts(limit=10)
    print(f'Response time: {time.time() - start:.2f}s')

asyncio.run(test())
"
```

**Solutions:**

1. **Adjust Resource Limits:**
   ```yaml
   # In compose.yml
   deploy:
     resources:
       limits:
         memory: 1G
         cpus: '1.0'
   ```

2. **Optimize Query Limits:**
   ```bash
   echo "MAX_ALERTS_PER_QUERY=100" >> .env.wazuh
   echo "REQUEST_TIMEOUT_SECONDS=60" >> .env.wazuh
   docker compose restart
   ```

3. **Wazuh Server Performance:**
   - Check Wazuh server resources
   - Consider indexer for large datasets
   - Optimize Wazuh configuration

## 🔧 Configuration Issues

### SSL Certificate Problems

**Symptoms:**
- SSL verification errors
- Certificate validation failures
- HTTPS connection refused

**Diagnosis:**
```bash
# Test SSL connection
openssl s_client -connect your-wazuh-host:55000

# Check certificate
docker compose exec wazuh-mcp-server python3 -c "
import ssl
import socket
context = ssl.create_default_context()
with socket.create_connection(('your-wazuh-host', 55000)) as sock:
    with context.wrap_socket(sock, server_hostname='your-wazuh-host') as ssock:
        print(ssock.version())
"
```

**Solutions:**

1. **Disable SSL Verification (Development):**
   ```bash
   echo "VERIFY_SSL=false" >> .env.wazuh
   docker compose restart
   ```

2. **Install Certificate:**
   ```bash
   # Copy certificate to container
   # Add to compose.yml volumes
   volumes:
     - ./certificates:/usr/local/share/ca-certificates
   ```

### Environment Variable Issues

**Symptoms:**
- Settings not taking effect
- Default values used instead of custom
- Configuration inconsistencies

**Diagnosis:**
```bash
# Check all environment variables
docker compose exec wazuh-mcp-server env | grep -E "WAZUH|MCP"

# Verify file loading
docker compose exec wazuh-mcp-server cat .env.wazuh

# Test configuration loading
docker compose exec wazuh-mcp-server python3 -c "
from src.wazuh_mcp_server.config import WazuhConfig
config = WazuhConfig.from_env()
print(f'Host: {config.wazuh_host}')
print(f'Port: {config.wazuh_port}')
print(f'Transport: {config.mcp_transport}')
"
```

**Solutions:**

1. **File Permissions:**
   ```bash
   chmod 644 .env.wazuh
   ```

2. **Variable Precedence:**
   - Environment variables override file
   - Restart container after changes
   - Check for typos in variable names

## 🆘 Emergency Recovery

### Complete Reset

When everything fails:

```bash
# 1. Stop all containers
docker compose down --volumes

# 2. Clean up containers and images
docker system prune -f

# 3. Reconfigure from scratch
rm -f .env.wazuh
./configure-wazuh.sh

# 4. Rebuild and start
docker compose up -d --build
```

### Get Interactive Shell

For advanced debugging:

```bash
# Access container shell
docker compose exec wazuh-mcp-server bash

# Or start new container with shell
docker compose run --rm wazuh-mcp-server bash

# Manual server start for debugging
python3 wazuh-mcp-server --debug
```

### Log Analysis

```bash
# Full logs with timestamps
docker compose logs -t wazuh-mcp-server

# Follow logs in real-time
docker compose logs -f --tail=100 wazuh-mcp-server

# Filter for errors only
docker compose logs wazuh-mcp-server | grep -i error

# Export logs for analysis
docker compose logs wazuh-mcp-server > debug.log
```

## 📞 Getting Help

### Before Asking for Help

1. **Run diagnostics:**
   ```bash
   docker compose exec wazuh-mcp-server python3 validate-production.py
   ```

2. **Collect information:**
   - Docker version: `docker --version`
   - Container logs: `docker compose logs wazuh-mcp-server`
   - Configuration: `cat .env.wazuh` (remove passwords)
   - System info: `uname -a`

3. **Test basic connectivity:**
   ```bash
   curl -k https://your-wazuh-host:55000
   ```

### Information to Include

When reporting issues:
- Exact error messages
- Steps to reproduce
- Environment details
- Configuration (sanitized)
- Docker and system versions

## 🔍 Common Error Messages

### "Connection refused"
- **Cause:** Wazuh Manager not reachable
- **Fix:** Check hostname, firewall, network connectivity

### "401 Unauthorized"
- **Cause:** Invalid credentials
- **Fix:** Verify username/password in Wazuh

### "SSL verification failed"
- **Cause:** Certificate issues
- **Fix:** Set `VERIFY_SSL=false` or install certificates

### "Port already in use"
- **Cause:** Another service using port 3000
- **Fix:** Change `MCP_PORT` to different value

### "No such file or directory"
- **Cause:** Missing configuration files
- **Fix:** Run `./configure-wazuh.sh` or create `.env.wazuh`

### "Permission denied"
- **Cause:** File permission issues
- **Fix:** Check file ownership and permissions

---

**💡 Pro Tip:** Most issues are resolved by re-running `./configure-wazuh.sh` to ensure correct configuration.