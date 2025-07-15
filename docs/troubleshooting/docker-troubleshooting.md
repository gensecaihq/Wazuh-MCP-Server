# Docker Troubleshooting Guide - Wazuh MCP Server v3.0.0

## Overview

This guide provides comprehensive troubleshooting steps for Docker-related issues with Wazuh MCP Server v3.0.0.

## Common Docker Issues

### Container Startup Issues

#### Issue: Containers fail to start
**Symptoms:**
- `docker compose up` fails with errors
- Containers exit immediately after startup
- Services show as "Exited" in `docker compose ps`

**Diagnosis:**
```bash
# Check container logs
docker compose logs -f wazuh-mcp-server

# Check container status
docker compose ps

# Check system resources
docker system df
```

**Solutions:**

1. **Check Docker Configuration**
   ```bash
   # Validate Docker Compose file
   docker compose config
   
   # Check for syntax errors
   docker compose -f docker compose.yml config
   ```

2. **Verify Environment Variables**
   ```bash
   # Check .env file
   cat .env
   
   # Validate required variables
   grep -E "(WAZUH_|JWT_|OAUTH_)" .env
   ```

3. **Check Resource Limits**
   ```bash
   # Check available memory
   free -h
   
   # Check disk space
   df -h
   
   # Increase Docker memory limits
   # Edit ~/.docker/daemon.json
   {
     "memory": "4g",
     "storage-driver": "overlay2"
   }
   ```

#### Issue: Image build failures
**Symptoms:**
- `docker build` fails with errors
- Missing dependencies during build
- Permission errors during image creation

**Diagnosis:**
```bash
# Check Docker build logs
docker build --no-cache -t wazuh-mcp-server:debug .

# Check Dockerfile syntax
docker run --rm -i hadolint/hadolint < Dockerfile
```

**Solutions:**

1. **Clean Build Environment**
   ```bash
   # Remove old images
   docker system prune -a
   
   # Build with clean cache
   docker build --no-cache -t wazuh-mcp-server:3.0.0 .
   ```

2. **Check Base Image**
   ```bash
   # Test base image
   docker pull python:3.9-slim
   
   # Check image architecture
   docker inspect python:3.9-slim | grep Architecture
   ```

3. **Fix Permission Issues**
   ```bash
   # Build with correct user
   docker build --build-arg USER_ID=$(id -u) --build-arg GROUP_ID=$(id -g) .
   
   # Check dockerfile user configuration
   grep -n "USER" Dockerfile
   ```

### Network Configuration Issues

#### Issue: Service connectivity problems
**Symptoms:**
- Services cannot communicate with each other
- External API calls fail
- Port binding errors

**Diagnosis:**
```bash
# Check Docker networks
docker network ls
docker network inspect wazuh-mcp-server_default

# Test connectivity between containers
docker exec -it wazuh-mcp-server ping redis
docker exec -it wazuh-mcp-server ping prometheus
```

**Solutions:**

1. **Network Configuration**
   ```bash
   # Create custom network
   docker network create wazuh-mcp-network
   
   # Update docker compose.yml
   networks:
     default:
       external:
         name: wazuh-mcp-network
   ```

2. **Port Conflicts**
   ```bash
   # Check port usage
   netstat -tulpn | grep :8443
   
   # Change port in docker compose.yml
   ports:
     - "8444:8443"  # Use different external port
   ```

3. **DNS Resolution**
   ```bash
   # Add custom DNS
   # In docker compose.yml
   services:
     wazuh-mcp-server:
       dns:
         - 8.8.8.8
         - 8.8.4.4
   ```

### Volume and Storage Issues

#### Issue: Data persistence problems
**Symptoms:**
- Data lost after container restart
- Permission denied errors
- Volume mounting failures

**Diagnosis:**
```bash
# Check volume mounts
docker volume ls
docker volume inspect wazuh-mcp-server_data

# Check mount permissions
docker exec -it wazuh-mcp-server ls -la /app/data
```

**Solutions:**

1. **Volume Permissions**
   ```bash
   # Fix volume permissions
   sudo chown -R 1000:1000 ./data
   
   # Update docker compose.yml
   volumes:
     - ./data:/app/data:rw
     - ./logs:/app/logs:rw
   ```

2. **Named Volumes**
   ```bash
   # Use named volumes instead of bind mounts
   # In docker compose.yml
   volumes:
     wazuh-mcp-data:
       driver: local
   
   services:
     wazuh-mcp-server:
       volumes:
         - wazuh-mcp-data:/app/data
   ```

3. **Storage Driver Issues**
   ```bash
   # Check storage driver
   docker info | grep "Storage Driver"
   
   # Change storage driver if needed
   # Edit /etc/docker/daemon.json
   {
     "storage-driver": "overlay2"
   }
   ```

### Authentication and Security Issues

#### Issue: OAuth2 authentication failures
**Symptoms:**
- Authentication endpoints return 401/403 errors
- Token generation fails
- SSL/TLS certificate issues

**Diagnosis:**
```bash
# Test OAuth2 endpoints
curl -k -X POST http://localhost:8443/oauth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&client_id=wazuh-mcp-client&client_secret=your-secret"

# Check JWT configuration
docker exec -it wazuh-mcp-server env | grep JWT
```

**Solutions:**

1. **JWT Secret Configuration**
   ```bash
   # Generate secure JWT secret
   openssl rand -base64 32
   
   # Update .env file
   JWT_SECRET_KEY=your-generated-secret-key
   
   # Restart containers
   docker compose restart
   ```

2. **SSL Certificate Issues**
   ```bash
   # Check certificate validity
   openssl x509 -in certs/server.crt -text -noout
   
   # Generate new self-signed certificate
   openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes
   
   # Update certificate permissions
   chmod 600 certs/server.key
   chmod 644 certs/server.crt
   ```

3. **Client Configuration**
   ```bash
   # Validate OAuth2 client
   docker exec -it wazuh-mcp-server python3 -c "
   from wazuh_mcp_server.auth.oauth2 import OAuth2Manager
   oauth = OAuth2Manager()
   print(oauth.get_client('wazuh-mcp-client'))
   "
   ```

### Performance and Resource Issues

#### Issue: High memory usage
**Symptoms:**
- Containers consuming excessive memory
- OOM (Out of Memory) kills
- System slowdown

**Diagnosis:**
```bash
# Check memory usage
docker stats --no-stream

# Check container resource limits
docker inspect wazuh-mcp-server | grep -A 10 "Memory"

# Monitor system resources
htop
```

**Solutions:**

1. **Memory Limits**
   ```bash
   # Set memory limits in docker compose.yml
   services:
     wazuh-mcp-server:
       deploy:
         resources:
           limits:
             memory: 1G
           reservations:
             memory: 512M
   ```

2. **Optimize Application**
   ```bash
   # Enable memory optimization
   # In .env file
   ENABLE_MEMORY_OPTIMIZATION=true
   MAX_CACHE_SIZE=1000
   CACHE_TTL=300
   ```

3. **Resource Monitoring**
   ```bash
   # Enable resource monitoring
   # In docker compose.yml
   services:
     wazuh-mcp-server:
       logging:
         driver: json-file
         options:
           max-size: "10m"
           max-file: "3"
   ```

#### Issue: Slow response times
**Symptoms:**
- API requests take too long
- Timeouts in Claude Desktop
- High CPU usage

**Diagnosis:**
```bash
# Check response times
curl -w "@curl-format.txt" -o /dev/null -s http://localhost:8443/health

# Monitor container performance
docker exec -it wazuh-mcp-server python3 -c "
import psutil
print(f'CPU: {psutil.cpu_percent()}%')
print(f'Memory: {psutil.virtual_memory().percent}%')
"
```

**Solutions:**

1. **Performance Optimization**
   ```bash
   # Enable performance optimizations
   # In .env file
   ENABLE_PARALLEL_PROCESSING=true
   MAX_CONCURRENT_REQUESTS=20
   ENABLE_INTELLIGENT_CACHING=true
   ```

2. **Database Optimization**
   ```bash
   # Redis optimization
   # In docker compose.yml
   redis:
     command: redis-server --maxmemory 256mb --maxmemory-policy allkeys-lru
   ```

3. **Load Balancing**
   ```bash
   # Enable load balancing
   docker compose -f docker compose.ha.yml up -d
   ```

### Monitoring and Logging Issues

#### Issue: Missing metrics or logs
**Symptoms:**
- Prometheus metrics not available
- Grafana dashboards empty
- Application logs missing

**Diagnosis:**
```bash
# Check Prometheus targets
curl -s http://localhost:9090/api/v1/targets | jq '.data.activeTargets'

# Check log files
docker exec -it wazuh-mcp-server ls -la /app/logs/

# Check Grafana connectivity
curl -f http://localhost:3000/api/health
```

**Solutions:**

1. **Metrics Configuration**
   ```bash
   # Enable metrics in .env
   ENABLE_METRICS=true
   METRICS_PORT=9090
   
   # Check metrics endpoint
   curl http://localhost:8443/metrics
   ```

2. **Logging Configuration**
   ```bash
   # Enable structured logging
   # In .env file
   LOG_FORMAT=json
   LOG_LEVEL=INFO
   ENABLE_AUDIT_LOG=true
   
   # Check log output
   docker compose logs -f wazuh-mcp-server
   ```

3. **Monitoring Stack**
   ```bash
   # Deploy full monitoring stack
   docker compose -f docker compose.ha.yml up -d prometheus grafana alertmanager
   
   # Import Grafana dashboards
   curl -X POST http://admin:admin@localhost:3000/api/dashboards/db \
     -H "Content-Type: application/json" \
     -d @config/grafana/dashboards/wazuh-mcp-overview.json
   ```

### High Availability Issues

#### Issue: Load balancer not working
**Symptoms:**
- Requests not distributed across instances
- Single point of failure
- Health check failures

**Diagnosis:**
```bash
# Check HAProxy stats
curl http://localhost:8080/stats

# Check backend health
curl -f http://localhost:8443/health
curl -f http://localhost:8444/health
curl -f http://localhost:8445/health
```

**Solutions:**

1. **HAProxy Configuration**
   ```bash
   # Check HAProxy configuration
   docker exec -it haproxy haproxy -f /usr/local/etc/haproxy/haproxy.cfg -c
   
   # Reload HAProxy configuration
   docker exec -it haproxy haproxy -f /usr/local/etc/haproxy/haproxy.cfg -sf $(pidof haproxy)
   ```

2. **Health Check Configuration**
   ```bash
   # Update health check settings
   # In config/haproxy.cfg
   backend wazuh-mcp-servers
     balance roundrobin
     option httpchk GET /health
     server server1 wazuh-mcp-server-1:8443 check inter 30s
     server server2 wazuh-mcp-server-2:8443 check inter 30s
     server server3 wazuh-mcp-server-3:8443 check inter 30s
   ```

3. **Scaling Configuration**
   ```bash
   # Scale services
   docker compose up -d --scale wazuh-mcp-server=3
   
   # Check service discovery
   docker exec -it haproxy nslookup wazuh-mcp-server
   ```

## Development and Testing Issues

### Issue: Development environment problems
**Symptoms:**
- Hot reload not working
- Debug mode not enabled
- Test failures in containers

**Diagnosis:**
```bash
# Check development configuration
docker compose -f docker compose.dev.yml config

# Check file watching
docker exec -it wazuh-mcp-server-dev ls -la /app/src/
```

**Solutions:**

1. **Development Setup**
   ```bash
   # Use development compose file
   docker compose -f docker compose.dev.yml up -d
   
   # Enable debug mode
   # In .env.dev
   DEBUG=true
   LOG_LEVEL=DEBUG
   ENABLE_HOT_RELOAD=true
   ```

2. **Volume Binding for Development**
   ```bash
   # Bind source code for development
   # In docker compose.dev.yml
   volumes:
     - ./src:/app/src:rw
     - ./tests:/app/tests:rw
   ```

3. **Test Configuration**
   ```bash
   # Run tests in container
   docker exec -it wazuh-mcp-server-dev python3 -m pytest tests/
   
   # Run specific test
   docker exec -it wazuh-mcp-server-dev python3 -m pytest tests/test_oauth2.py -v
   ```

## Emergency Procedures

### Complete System Recovery

#### Step 1: Stop All Services
```bash
# Stop all containers
docker compose down

# Stop and remove all containers
docker compose down --remove-orphans

# Remove all volumes (WARNING: This will delete all data)
docker compose down -v
```

#### Step 2: Clean Docker Environment
```bash
# Remove all containers
docker container prune -f

# Remove all images
docker image prune -a -f

# Remove all volumes
docker volume prune -f

# Remove all networks
docker network prune -f
```

#### Step 3: Rebuild and Restart
```bash
# Rebuild images
docker compose build --no-cache

# Start services
docker compose up -d

# Verify services
docker compose ps
```

### Backup and Restore

#### Backup Docker Volumes
```bash
# Create backup
docker run --rm -v wazuh-mcp-data:/data -v $(pwd):/backup ubuntu tar czf /backup/wazuh-mcp-backup.tar.gz /data

# Backup database
docker exec -it redis redis-cli SAVE
docker cp redis:/data/dump.rdb ./backup/
```

#### Restore from Backup
```bash
# Restore volume
docker run --rm -v wazuh-mcp-data:/data -v $(pwd):/backup ubuntu tar xzf /backup/wazuh-mcp-backup.tar.gz -C /

# Restore database
docker cp ./backup/dump.rdb redis:/data/
docker exec -it redis redis-cli DEBUG RESTART
```

## Diagnostic Tools

### Container Health Check Script

```bash
#!/bin/bash
# docker-health-check.sh

set -euo pipefail

echo "=== Docker Health Check ==="
echo "Date: $(date)"
echo

# Check Docker daemon
echo "Docker daemon status:"
docker version
echo

# Check containers
echo "Container status:"
docker compose ps
echo

# Check logs
echo "Recent logs:"
docker compose logs --tail=20 wazuh-mcp-server
echo

# Check resources
echo "Resource usage:"
docker stats --no-stream
echo

# Check networks
echo "Network status:"
docker network ls
echo

# Check volumes
echo "Volume status:"
docker volume ls
echo

# Test connectivity
echo "Connectivity tests:"
curl -f http://localhost:8443/health && echo "✓ Health check passed" || echo "✗ Health check failed"
curl -f http://localhost:9090/metrics && echo "✓ Metrics available" || echo "✗ Metrics unavailable"
echo

echo "=== Health Check Complete ==="
```

### Performance Monitoring Script

```bash
#!/bin/bash
# docker-performance-monitor.sh

set -euo pipefail

echo "=== Performance Monitoring ==="
echo "Date: $(date)"
echo

# Container stats
docker stats --no-stream --format "table {{.Container}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}\t{{.BlockIO}}"

# System resources
echo
echo "System resources:"
echo "Memory: $(free -h | grep Mem | awk '{print $3"/"$2}')"
echo "CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
echo "Disk: $(df -h / | tail -1 | awk '{print $5}')"
echo

# Application metrics
echo "Application metrics:"
curl -s http://localhost:8443/metrics | grep -E "(request_count|response_time|error_rate)" | head -10
echo

echo "=== Performance Monitoring Complete ==="
```

## Best Practices

### Docker Configuration

1. **Use Multi-stage Builds**
   ```dockerfile
   FROM python:3.9-slim as builder
   WORKDIR /app
   COPY requirements.txt .
   RUN pip install --user -r requirements.txt
   
   FROM python:3.9-slim
   WORKDIR /app
   COPY --from=builder /root/.local /root/.local
   COPY src/ .
   ```

2. **Optimize Image Size**
   ```dockerfile
   # Use slim base images
   FROM python:3.9-slim
   
   # Clean up after installations
   RUN apt-get update && apt-get install -y \
       build-essential \
       && rm -rf /var/lib/apt/lists/*
   ```

3. **Security Best Practices**
   ```dockerfile
   # Run as non-root user
   USER 1000:1000
   
   # Use read-only root filesystem
   # In docker compose.yml
   read_only: true
   tmpfs:
     - /tmp
     - /var/tmp
   ```

### Monitoring and Logging

1. **Structured Logging**
   ```yaml
   logging:
     driver: json-file
     options:
       max-size: "10m"
       max-file: "3"
   ```

2. **Health Checks**
   ```yaml
   healthcheck:
     test: ["CMD", "curl", "-f", "http://localhost:8443/health"]
     interval: 30s
     timeout: 10s
     retries: 3
   ```

3. **Resource Limits**
   ```yaml
   deploy:
     resources:
       limits:
         memory: 1G
         cpus: '0.5'
   ```

This comprehensive Docker troubleshooting guide should help resolve most issues encountered when deploying Wazuh MCP Server v3.0.0 in containerized environments.