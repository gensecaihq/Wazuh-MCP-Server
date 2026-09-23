# Troubleshooting Guide

Common issues and their solutions.

## MCP Endpoint Issues

### Testing the MCP Endpoint

```bash
# Without a token
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3000/mcp \
     -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"ping"}'
# Expected: 401 (auth required)

# With a token
curl -s -X POST http://localhost:3000/mcp \
     -H "Authorization: Bearer your-jwt-token" \
     -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
     -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
# Expected: 200 with an InitializeResult

# The legacy /sse transport answers 410 Gone — point clients at /mcp

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
docker compose logs wazuh-main-server

# Verify port availability
netstat -ln | grep 3000

# Check if container is healthy
docker inspect wazuh-main-server --format='{{.State.Health.Status}}'
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
# The key the server accepts is MCP_API_KEY from .env (keys are never logged)
grep ^MCP_API_KEY= .env

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
docker compose logs wazuh-main-server | grep -i "wazuh"
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
docker stats wazuh-main-server --no-stream

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
docker compose logs -f --timestamps wazuh-main-server

# Search for errors
docker compose logs wazuh-main-server | grep -i error

# Export logs for analysis
docker compose logs --since=24h wazuh-main-server > server.log
```

---

## Health Check

```bash
# Full readiness status (Wazuh/Indexer dependency checks)
curl -s http://localhost:3000/ready | jq .

# Prometheus metrics
curl -s http://localhost:3000/metrics | head -50

# Container health
docker inspect wazuh-main-server --format='{{json .State.Health}}' | jq .
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
