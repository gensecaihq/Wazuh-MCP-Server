# Advanced Features

Production-grade features for enterprise deployments.

## High Availability (HA)

The server includes production-grade HA features for maximum reliability.

### Circuit Breakers

- Automatically opens after 5 consecutive failures
- Prevents cascading failures to Wazuh API
- Recovers automatically after 60 seconds
- Falls back gracefully during outages

### Retry Logic

- Exponential backoff with jitter
- 3 retry attempts with 1-10 second delays
- Applies to all Wazuh API calls
- Handles transient network failures

### Graceful Shutdown

- Waits for active connections to complete (max 30s)
- Runs cleanup tasks before termination
- Prevents data loss during restarts
- Integrates with Docker health checks

**Implementation:** Automatically applied to all Wazuh API calls - no configuration required.

---

## Serverless Ready

Enable horizontally scalable, serverless deployments with external session storage.

### Default Mode: In-Memory Sessions

```bash
# Single-instance deployments (default)
docker compose up -d
```

| Pros | Cons |
|------|------|
| ✅ Zero configuration | ❌ Sessions lost on restart |
| ✅ Works immediately | ❌ Cannot scale horizontally |

### Serverless Mode: Redis Sessions

```bash
# Configure Redis in .env file
REDIS_URL=redis://redis:6379/0
SESSION_TTL_SECONDS=1800  # 30 minutes

# Deploy with Redis
docker compose -f compose.yml -f compose.redis.yml up -d
```

| Pros |
|------|
| ✅ Sessions persist across restarts |
| ✅ Horizontal scaling support |
| ✅ Serverless compatible (AWS Lambda, Cloud Run) |
| ✅ Automatic session expiration |

### Redis Setup

```yaml
# compose.redis.yml
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s

volumes:
  redis-data:
```

### Verification

```bash
# Check session storage mode
curl http://localhost:3000/health | jq '.session_storage'

# Output:
# {
#   "type": "InMemorySessionStore"  # or "RedisSessionStore"
#   "sessions_count": 5
# }
```

---

## Compact Output Mode

Reduce token usage by ~66% with compact output mode (enabled by default).

### Supported Tools

| Tool | Compact Format |
|------|----------------|
| `get_wazuh_alerts` | timestamp, agent, rule, IPs, syscheck, truncated logs |
| `search_security_events` | Same as alerts |
| `get_wazuh_vulnerabilities` | id, severity, description (120 chars), package, agent |
| `get_wazuh_critical_vulnerabilities` | Same as vulnerabilities |

### Usage

```bash
# Compact mode (default) - minimal JSON, essential fields only
curl -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer <token>" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_wazuh_alerts","arguments":{"limit":10}},"id":"1"}'

# Full mode - complete data with pretty-printing
curl -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer <token>" \
  -d '{"jsonrpc":"2.0","method":"tools/call","params":{"name":"get_wazuh_alerts","arguments":{"limit":10,"compact":false}},"id":"1"}'
```

### Token Savings

| Mode | Chars/alert | 100 alerts | Estimated Tokens |
|------|-------------|------------|------------------|
| Full | ~1,350 | 135K | ~33,750 |
| Compact | ~450 | 45K | ~11,300 |
| **Savings** | **67%** | **90K** | **~22,000** |

---

## MCP Protocol Compliance

Full compliance with MCP 2025-11-25 specification.

| Standard | Status |
|----------|--------|
| Streamable HTTP | ✅ `/mcp` endpoint with POST/GET/DELETE |
| Protocol Versioning | ✅ `MCP-Protocol-Version` header validation |
| Dynamic Streaming | ✅ JSON or SSE based on Accept header |
| Authentication | ✅ Bearer token (JWT) authentication |
| Security | ✅ HTTPS, origin validation, rate limiting |
| Legacy Support | ✅ Legacy `/sse` endpoint maintained |
| Session Management | ✅ `MCP-Session-Id` header, full lifecycle with DELETE |
| Prompts | ✅ `prompts/list` and `prompts/get` with 4 security prompts |
| Resources | ✅ `resources/list`, `resources/read`, `resources/templates/list` |
| Logging | ✅ `logging/setLevel` with RFC 5424 levels |
| Completion | ✅ `completion/complete` for argument suggestions |

**Full verification details:** [MCP_COMPLIANCE_VERIFICATION.md](../MCP_COMPLIANCE_VERIFICATION.md)

---

[← Back to README](../README.md)
