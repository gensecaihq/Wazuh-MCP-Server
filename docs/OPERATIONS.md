# Operations Guide

Day-to-day operations and maintenance tasks.

## Docker Compose Operations

### Deployment

```bash
# Standard deployment
docker compose up -d

# With the cross-platform deployment helper (configures MCP_API_KEY in .env)
python deploy.py

# (Legacy scripts deploy-production.sh / install.sh / deploy.bat are deprecated —
#  use `docker compose up -d` or `python deploy.py`.)

# Force rebuild
docker compose up -d --build --force-recreate
```

### Service Management

```bash
# View status
docker compose ps --format table

# View logs
docker compose logs -f --timestamps wazuh-main-server

# Restart service
docker compose restart wazuh-main-server

# Stop services
docker compose down --timeout 30

# Scale service (load testing)
docker compose up --scale wazuh-main-server=2 -d
```

### Cleanup

```bash
# Remove containers only
docker compose down

# Remove containers and volumes
docker compose down --volumes

# Full cleanup
docker compose down --volumes --remove-orphans
docker system prune -f
```

---

## Health Monitoring

### Application Health

```bash
# Quick health check
curl -s http://localhost:3000/health | jq '.status'

# Detailed readiness (Wazuh/Indexer checks)
curl -s http://localhost:3000/ready | jq .

# Container health status
docker inspect wazuh-main-server --format='{{.State.Health.Status}}'
```

### Prometheus Metrics

```bash
# View all metrics
curl http://localhost:3000/metrics

# Request count
curl -s http://localhost:3000/metrics | grep request_count

# Active connections
curl -s http://localhost:3000/metrics | grep active_connections
```

### Resource Usage

```bash
# Real-time stats
docker stats wazuh-main-server

# Formatted output
docker stats wazuh-main-server --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
```

---

## Log Management

### Viewing Logs

```bash
# Follow live logs
docker compose logs -f wazuh-main-server

# Last 100 lines
docker compose logs --tail=100 wazuh-main-server

# With timestamps
docker compose logs -f --timestamps wazuh-main-server
```

### Exporting Logs

```bash
# Last 24 hours
docker compose logs --since=24h wazuh-main-server > server.log

# Specific time range
docker compose logs --since="2024-01-01T00:00:00" --until="2024-01-02T00:00:00" wazuh-main-server > server.log
```

### Log Filtering

```bash
# Errors only
docker compose logs wazuh-main-server | grep -i error

# Wazuh connections
docker compose logs wazuh-main-server | grep -i wazuh

# Authentication events
docker compose logs wazuh-main-server | grep -i auth
```

---

## Maintenance Tasks

### Updates

```bash
# Pull latest images
docker compose pull

# Update and restart
docker compose pull && docker compose up -d

# Update with rebuild
docker compose build --pull --no-cache && docker compose up -d
```

### Backups

```bash
# Backup configuration
tar -czf backup-$(date +%Y%m%d).tar.gz .env compose.yml

# Backup with logs
tar -czf backup-full-$(date +%Y%m%d).tar.gz .env compose.yml logs/
```

### Security Updates

```bash
# Check for vulnerabilities
docker scout cves wazuh-main-server:latest

# Force security update
docker compose build --pull --no-cache
docker compose up -d
```

---

## API Reference

### MCP Protocol Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp` | GET/POST/DELETE | **Recommended** - Streamable HTTP (MCP 2026-07-28 + legacy) |
| `/sse` | GET | Legacy SSE endpoint |
| `/` | GET/POST | JSON-RPC 2.0 endpoint (authenticated) |
| `/health` | GET | Liveness probe — 200 while the process is up (no dependency checks; use this for the container/orchestrator healthcheck) |
| `/ready` | GET | Readiness probe — verifies Wazuh Manager/Indexer reachability; 503 when a dependency is down |
| `/metrics` | GET | Prometheus metrics (custom registry) |
| `/docs` | GET | OpenAPI documentation |

### Authentication Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/token` | POST | Exchange API key for JWT (bearer mode) |
| `/.well-known/oauth-authorization-server` | GET | OAuth 2.0 discovery (RFC 8414) |
| `/.well-known/oauth-protected-resource` | GET | OAuth protected-resource metadata (RFC 9728) |
| `/oauth/authorize` | GET | OAuth authorization |
| `/oauth/token` | POST | OAuth token exchange |
| `/oauth/revoke` | POST | OAuth token revocation (RFC 7009) |
| `/oauth/register` | POST | Dynamic Client Registration (only when `OAUTH_ENABLE_DCR=true`) |

### Quick API Tests

```bash
# Health check
curl http://localhost:3000/health

# Get token
curl -X POST http://localhost:3000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "your-api-key"}'

# List tools
curl -X POST http://localhost:3000/ \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/list"}'
```

---

## Performance Tuning

### Resource Limits

Edit `compose.yml`:

```yaml
deploy:
  resources:
    limits:
      cpus: '2.0'        # Increase for high load
      memory: 1024M      # Increase for more connections
    reservations:
      cpus: '0.5'
      memory: 256M
```

### Connection Limits

Environment variables:

```env
# Rate limiting
RATE_LIMIT_REQUESTS=200     # Requests allowed per window
RATE_LIMIT_WINDOW=60        # Window in seconds

# Session management
SESSION_TTL_SECONDS=3600    # Session timeout
```

---

[← Back to README](../README.md)
