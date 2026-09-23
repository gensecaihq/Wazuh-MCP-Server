# Advanced Features

Resilience, scaling, output formats, tool exposure and protocol details. Configuration variables are listed in [configuration.md](configuration.md).

## Resilience

### Retries

- Wazuh Manager API reads (GET) and Indexer searches are retried up to 3 attempts in total, with exponential backoff between 1 and 10 seconds.
- Manager API calls retry only transient failures: connection errors, timeouts, `429` and `5xx`. Other `4xx` responses are returned immediately.
- State-changing Manager calls (PUT/DELETE, i.e. active response) are never retried, because they are not idempotent.

### Circuit breakers

- Each Wazuh client has a circuit breaker for the Manager API and one for the Indexer. A breaker opens after 5 consecutive failures and allows a trial request after 60 seconds.
- The optional You.com lookup (`search_external_context`) has its own breaker, so an external outage cannot block Wazuh calls.
- In [multi-cluster](MULTI_CLUSTER.md) mode every cluster has its own client and breakers.

### Shutdown

On SIGTERM the server stops background tasks, closes the session-store connection (Redis sessions are left in place for other replicas), closes the Wazuh clients for every configured cluster, and releases connection pools.

### Response limits

- Each tool result is capped at `MAX_TOOL_RESPONSE_CHARS` (default 1,000,000 characters); longer results are truncated with a note asking for a narrower query.
- Credentials in log text (`password=`, `token=`, `Authorization:` and similar) are redacted from every tool result.
- When process memory exceeds `MAX_MEMORY_MB` (default 512, minimum 64), non-probe requests receive `503` and `/ready` reports `memory: over_limit`.

## Scaling and session storage

Only legacy-handshake clients (protocol `2025-11-25` and earlier) use sessions. Requests using the `2026-07-28` revision are stateless: no session is created or stored, and any replica can serve them.

### In-memory (default)

Sessions live in the server process and are lost on restart. Clients then receive `404` for their session ID and start a new session with `initialize`. Sessions expire after 30 minutes of inactivity.

The startup log shows:

```
Initialized InMemorySessionStore (single-instance mode)
```

### Redis

Set `REDIS_URL` to share legacy sessions between replicas and keep them across restarts. The `redis` client is included in the image.

```bash
# .env
REDIS_URL=redis://redis:6379/0
SESSION_TTL_SECONDS=1800   # positive integer; an invalid value stops startup
```

There is no Redis service in `compose.yml`. A minimal overlay, saved as `compose.redis.yml` next to `compose.yml`:

```yaml
services:
  redis:
    image: redis:7-alpine
    # No published port: Redis holds session data without authentication.
    volumes:
      - redis-data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s

  wazuh-main-server:
    depends_on:
      redis:
        condition: service_healthy

volumes:
  redis-data:
```

```bash
docker compose -f compose.yml -f compose.redis.yml up -d
docker compose logs wazuh-main-server | grep -i sessionstore
# RedisSessionStore configured with TTL=1800s
```

With `REDIS_URL` set there is no fallback to in-memory storage. If Redis is unreachable, requests that need the session store fail with `503`, `Retry-After: 5` and `{"error": "Session store unavailable; retry shortly"}`, rather than a `404` that would tell clients to re-initialize.

### Running several replicas

- Use the same `AUTH_SECRET_KEY` on every replica. It signs bearer and OAuth access tokens and derives API-key hashes.
- Use Redis if any client uses the legacy handshake.
- OAuth authorization codes, refresh tokens and the revocation list are per process. Route `/oauth/*` to a consistent replica (sticky sessions) or run one replica in OAuth mode.
- Rate-limit counters are per process, so the effective limit scales with the replica count.

## Output formats

### Compact mode

`get_wazuh_alerts`, `search_security_events`, `get_wazuh_vulnerabilities` and `get_wazuh_critical_vulnerabilities` take a `compact` argument, default `true`.

| Tool | Compact output |
|------|----------------|
| Alerts and security events | `timestamp`, agent `id`/`name`, rule `id`/`level`/`description`/`groups` (and `mitre` when present), `srcip`, `dstip`, syscheck `path`/`event`, `full_log` truncated to 300 characters |
| Vulnerabilities | `id`/`cve`, `severity`, `description` truncated to 120 characters, `reference`, `published_at`, package `name`/`version`, agent `id`/`name` |

Compact results are serialized without indentation. Pass `"compact": false` for the full documents, pretty-printed:

```json
{"name": "get_wazuh_alerts", "arguments": {"limit": 10, "compact": false}}
```

### GCF encoding

`RESPONSE_FORMAT=gcf` encodes the results of the same four tools in Graph Compact Format, which factors repeated field names into a header. The encoding is lossless and applies on top of the `compact` setting. `gcf-python` is included in the image (`pip install 'wazuh-mcp-server[gcf]'` otherwise); if it is missing or encoding fails, the server logs a warning and returns JSON. The default is `json`.

## Tool exposure

### Toolsets

`WAZUH_TOOLSETS` limits the catalogue to a comma-separated list of groups; empty or `all` exposes everything. `WAZUH_DISABLED_TOOLS` removes individual tools. Hidden tools are absent from `tools/list` and refused by `tools/call`. Unknown toolset or tool names stop startup.

| Toolset | Tools |
|---------|------:|
| `alerts` | 5 |
| `agents` | 6 |
| `vulnerabilities` | 3 |
| `analysis` | 5 |
| `web_search` | 1 (`search_external_context`, the only tool that sends data off-box, to You.com) |
| `compliance` | 6 |
| `system` | 10, plus `list_wazuh_clusters` in multi-cluster mode |
| `response` | 19 (14 write tools and 5 read-only verification tools) |

```bash
WAZUH_TOOLSETS=alerts,agents,vulnerabilities,analysis
WAZUH_DISABLED_TOOLS=wazuh_restart,wazuh_active_response
```

### Scopes

Tools require `wazuh:read` (41 tools) or `wazuh:write` (14 tools). Write tools are omitted from `tools/list` for tokens without `wazuh:write`, and refused if called. Every write-tool call that passes the scope and confirmation checks is logged to the `wazuh_mcp_server.audit` logger with the principal, session and arguments.

`WAZUH_REQUIRE_ACTION_CONFIRMATION=true` additionally requires `confirm=true` on every write tool and adds that argument to their schemas.

### Tool annotations

Every tool carries MCP tool annotations derived from its scope:

| Tools | Annotations |
|-------|-------------|
| Read tools | `readOnlyHint: true`, `openWorldHint: false` (`true` for `search_external_context`) |
| Write tools | `readOnlyHint: false`, `destructiveHint: true`, `idempotentHint: false`, `openWorldHint: false` |
| Reversal tools (`wazuh_unisolate_host`, `wazuh_enable_user`, `wazuh_restore_file`, `wazuh_firewall_allow`, `wazuh_host_allow`) | As write tools, but `destructiveHint: false` |

Annotations are hints for clients deciding when to ask for approval. Authorization is enforced by scope on the server.

Every input schema sets `additionalProperties: false`, and the server enforces it: an unknown argument returns a tool error listing the valid arguments instead of being silently ignored.

## Rate limiting

| Traffic | Limit | Key |
|---------|-------|-----|
| `/mcp` and `/` | 100 requests / 60 s (fixed) | Authenticated principal + client IP |
| Failed authentication on those endpoints | Same budget | Client IP; repeated `401`s turn into `429` |
| Other routes (`/auth/token`, `/oauth/*`, …) | `RATE_LIMIT_REQUESTS` per `RATE_LIMIT_WINDOW` seconds (default 100 / 60) | Client IP |
| `/health`, `/ready`, `/metrics` | Not limited | — |

A `429` carries `Retry-After`. Client IPs are taken from `X-Forwarded-For` / `X-Real-IP` only when the direct peer is loopback or listed in `TRUSTED_PROXIES`.

## Health, readiness and metrics

- `/health` is a liveness probe. It returns `200` while the process is serving and does not contact Wazuh, so a SIEM outage does not restart the container.
- `/ready` checks the Manager API, the Indexer (if configured) and memory headroom, and returns `503` when any is unhealthy. Results are cached for 5 seconds and evaluated one at a time, so frequent probes do not load the Manager. In multi-cluster mode only the environment-configured cluster is probed.
- `/metrics` exposes Prometheus metrics, including `wazuh_mcp_requests_total`, `wazuh_mcp_request_duration_seconds`, `wazuh_mcp_tool_executions_total`, `wazuh_mcp_tool_duration_seconds`, `wazuh_mcp_auth_attempts_total`, `wazuh_mcp_rate_limit_hits_total` and `wazuh_mcp_errors_total`. It is unauthenticated; restrict it at the reverse proxy.

Every response carries `X-Content-Type-Options`, `X-Frame-Options`, `X-XSS-Protection`, `Strict-Transport-Security` and a `Content-Security-Policy` header, and an `X-Correlation-ID` header (taken from the request's `X-Correlation-ID` or `X-Request-ID`, or generated). The same ID appears in JSON-RPC error data.

## MCP protocol support

The server is dual-era:

| Revision | Behaviour |
|----------|-----------|
| `2026-07-28` | Stateless. Each request carries `MCP-Protocol-Version`, `Mcp-Method`, `Mcp-Name` (for `tools/call`, `prompts/get`, `resources/read`) and `params._meta["io.modelcontextprotocol/protocolVersion"]`; header/body mismatches are rejected. `server/discover` is available; `initialize`, `ping` and `logging/setLevel` are not. List and read results include `ttlMs` and `cacheScope: "private"`. Batches are rejected. |
| `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05` | `initialize` handshake. The response sets `MCP-Session-Id`; sessions are created only by `initialize` (or a GET stream) and ended with `DELETE /mcp`. |

| Feature | Support |
|---------|---------|
| Transport | Streamable HTTP on `/mcp` (POST, GET for SSE, DELETE). `/sse` returns `410`. |
| Responses | POST requests are answered with JSON. GET with `Accept: text/event-stream` opens an SSE stream; GET without it returns `405`. |
| Tools | 55 (56 in multi-cluster mode) |
| Prompts | 5: `security_investigation`, `threat_hunt`, `compliance_audit`, `vulnerability_assessment`, `iso27001_assessment` |
| Resources | 6 resources and 3 resource templates; no subscriptions |
| Completions | `completion/complete` |
| Logging | `logging/setLevel` (legacy handshake only) |
| Origin validation | Requests with an `Origin` header not in `ALLOWED_ORIGINS` get `403` |

See [MCP_COMPLIANCE_VERIFICATION.md](../MCP_COMPLIANCE_VERIFICATION.md) for the detailed conformance notes.

---

[Configuration](configuration.md) · [Operations](OPERATIONS.md) · [Back to README](../README.md)
