# Troubleshooting Guide

Common issues and their solutions.

## MCP Endpoint Issues

### Testing SSE Endpoint

```bash
# Test SSE endpoint authentication
curl -I http://localhost:3000/sse
# Expected: 401 Unauthorized (good - auth required)

# Test with valid token
curl -H "Authorization: Bearer your-jwt-token" \
     -H "Origin: http://localhost" \
     -H "Accept: text/event-stream" \
     http://localhost:3000/sse
# Expected: 200 OK with SSE stream

# Get new authentication token
curl -X POST http://localhost:3000/auth/token \
     -H "Content-Type: application/json" \
     -d '{"api_key": "your-api-key"}'
```

---

## Claude Desktop Connection Issues

```bash
# Verify Claude Desktop can reach the server
curl http://localhost:3000/health
# Expected: {"status": "healthy"}

# Check CORS configuration
grep ALLOWED_ORIGINS .env
# Should include: https://claude.ai,https://*.anthropic.com
```

**Common Causes:**
- Server not running or not accessible via HTTPS
- CORS not configured for Claude domains
- Using JSON config instead of Connectors UI (see [Claude Integration Guide](CLAUDE_INTEGRATION.md))

---

## Connection Refused

```bash
# Check service status
docker compose ps
docker compose logs wazuh-mcp-remote-server

# Verify port availability
netstat -ln | grep 3000

# Check if container is healthy
docker inspect wazuh-mcp-remote-server --format='{{.State.Health.Status}}'
```

**Common Causes:**
- Container not running
- Port 3000 already in use
- Docker network issues

---

## Authentication Errors

### Wazuh API Authentication

```bash
# Verify Wazuh credentials
curl -u "$WAZUH_USER:$WAZUH_PASS" "$WAZUH_HOST:$WAZUH_PORT/"

# Check environment variables
grep -E "WAZUH_USER|WAZUH_HOST" .env
```

### MCP API Key Issues

```bash
# Check API key in server logs
docker compose logs wazuh-mcp-remote-server | grep "API key"

# Exchange API key for token
curl -X POST http://localhost:3000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "wazuh_your-generated-api-key"}'
```

---

## SSL/TLS Issues

```bash
# Disable SSL verification for testing
echo "WAZUH_VERIFY_SSL=false" >> .env
docker compose up -d

# Check Wazuh SSL certificate
openssl s_client -connect your-wazuh-server:55000 </dev/null 2>/dev/null | openssl x509 -noout -dates
```

---

## Wazuh Connectivity Issues

### Wazuh Manager API

```bash
# Test direct API access
curl -k -u admin:password https://wazuh-server:55000/

# Check server logs for connection errors
docker compose logs wazuh-mcp-remote-server | grep -i "wazuh"
```

### Wazuh Indexer (Vulnerabilities)

For Wazuh 4.8.0+, vulnerability data requires the Indexer:

```bash
# Test Indexer connectivity
curl -k -u admin:password https://wazuh-indexer:9200/

# Verify Indexer configuration
grep -E "WAZUH_INDEXER" .env
```

**Required for vulnerability tools:**
```env
WAZUH_INDEXER_HOST=your-indexer-host
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=your-password
```

---

## Performance Issues

### High Memory Usage

```bash
# Check container resource usage
docker stats wazuh-mcp-remote-server --no-stream

# View configured limits
grep -E "memory|cpus" compose.yml
```

### Slow Response Times

```bash
# Check Wazuh API latency
time curl -k -u admin:password https://wazuh-server:55000/agents

# Check server metrics
curl http://localhost:3000/metrics | grep request_duration
```

---

## Log Analysis

```bash
# Follow live logs
docker compose logs -f --timestamps wazuh-mcp-remote-server

# Search for errors
docker compose logs wazuh-mcp-remote-server | grep -i error

# Export logs for analysis
docker compose logs --since=24h wazuh-mcp-remote-server > server.log
```

---

## Health Check

```bash
# Full health status
curl -s http://localhost:3000/health | jq .

# Prometheus metrics
curl -s http://localhost:3000/metrics | head -50

# Container health
docker inspect wazuh-mcp-remote-server --format='{{json .State.Health}}' | jq .
```

---

## Reset and Clean Start

```bash
# Stop and remove containers
docker compose down

# Remove volumes (WARNING: deletes data)
docker compose down --volumes

# Clean rebuild
docker compose build --no-cache
docker compose up -d
```

---

## Support Resources

- **Documentation**: [MCP Specification](https://modelcontextprotocol.io/)
- **Issues**: [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)

---

[← Back to README](../README.md)
