# Operations Guide

Day-to-day operations and maintenance tasks.

## Docker Compose Operations

### Deployment

```bash
# Standard deployment
docker compose up -d

# With deployment script (recommended)
python deploy.py          # Cross-platform
./deploy-production.sh    # Linux/macOS
deploy.bat                # Windows

# Force rebuild
docker compose up -d --build --force-recreate
```

### Service Management

```bash
# View status
docker compose ps --format table

# View logs
docker compose logs -f --timestamps wazuh-mcp-remote-server

# Restart service
docker compose restart wazuh-mcp-remote-server

# Stop services
docker compose down --timeout 30

# Scale service (load testing)
docker compose up --scale wazuh-mcp-remote-server=2 -d
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

# Detailed health
curl -s http://localhost:3000/health | jq .

# Container health status
docker inspect wazuh-mcp-remote-server --format='{{.State.Health.Status}}'
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
docker stats wazuh-mcp-remote-server

# Formatted output
docker stats wazuh-mcp-remote-server --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.NetIO}}"
```

---

## Log Management

### Viewing Logs

```bash
# Follow live logs
docker compose logs -f wazuh-mcp-remote-server

# Last 100 lines
docker compose logs --tail=100 wazuh-mcp-remote-server

# With timestamps
docker compose logs -f --timestamps wazuh-mcp-remote-server
```

### Exporting Logs

```bash
# Last 24 hours
docker compose logs --since=24h wazuh-mcp-remote-server > server.log

# Specific time range
docker compose logs --since="2024-01-01T00:00:00" --until="2024-01-02T00:00:00" wazuh-mcp-remote-server > server.log
```

### Log Filtering

```bash
# Errors only
docker compose logs wazuh-mcp-remote-server | grep -i error

# Wazuh connections
docker compose logs wazuh-mcp-remote-server | grep -i wazuh

# Authentication events
docker compose logs wazuh-mcp-remote-server | grep -i auth
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
docker scout cves wazuh-mcp-remote-server:latest

# Force security update
docker compose build --pull --no-cache
docker compose up -d
```

---

## API Reference

### MCP Protocol Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp` | GET/POST | **Recommended** - Streamable HTTP (2025-11-25) |
| `/sse` | GET | Legacy SSE endpoint |
| `/` | POST | JSON-RPC 2.0 endpoint |
| `/health` | GET | Health check |
| `/metrics` | GET | Prometheus metrics |
| `/docs` | GET | OpenAPI documentation |

### Authentication Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/auth/token` | POST | Exchange API key for JWT |
| `/.well-known/oauth-authorization-server` | GET | OAuth discovery |
| `/oauth/authorize` | GET | OAuth authorization |
| `/oauth/token` | POST | OAuth token exchange |
| `/oauth/register` | POST | Dynamic Client Registration |

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
RATE_LIMIT_REQUESTS=200     # Requests per minute
RATE_LIMIT_WINDOW=60        # Window in seconds

# Session management
SESSION_TTL_SECONDS=3600    # Session timeout
MAX_SESSIONS=1000           # Maximum concurrent sessions
```

---

[← Back to README](../README.md)
