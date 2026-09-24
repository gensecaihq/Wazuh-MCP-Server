# Operations Guide

Running, monitoring and maintaining a deployed Wazuh MCP Server. For the configuration variables themselves, see the [Configuration Reference](configuration.md).

## Deployment

### Docker Compose

```bash
cp .env.example .env        # then set WAZUH_*, AUTH_SECRET_KEY and MCP_API_KEY
docker compose up -d
```

What `compose.yml` does:

- **Image:** builds `wazuh-main-server:${VERSION:-4.3.0}` locally from the `Dockerfile` and runs it as the `wazuh-main-server` container.
- **Environment:** reads `.env` and forces `ENVIRONMENT=production`, so the server refuses to start without `AUTH_SECRET_KEY` and write tools require `confirm=true` (see [Configuration](configuration.md#production-requirements)). The server also refuses to start without `WAZUH_HOST`, `WAZUH_USER` and `WAZUH_PASS`.
- **Port:** publishes port 3000 on `${MCP_BIND:-127.0.0.1}:${MCP_PORT:-3000}`. The loopback default expects a TLS-terminating reverse proxy on the same host.
- **Container hardening:** read-only root filesystem, all capabilities dropped, `no-new-privileges`, and a 64 MB tmpfs for `/tmp`.
- **Mounts:** mounts `./config` read-only at `/app/config`, for `clusters.json`. A commented `./certs:/app/certs:ro` line is provided for a CA bundle; enable it and set `WAZUH_CA_BUNDLE=/app/certs/ca.pem` (see [Manager TLS](configuration.md#manager-tls)).
- **Limits:** 1 CPU and 512 MB of memory.

### Deployment helper

`deploy.py` wraps the same Compose file. On Windows, `deploy.bat` runs it with the same arguments.

```bash
python deploy.py            # same as: python deploy.py deploy
python deploy.py status     # container status and resource usage
python deploy.py logs       # follow logs
python deploy.py restart
python deploy.py stop       # docker compose down
python deploy.py cleanup    # docker compose down --volumes --remove-orphans
```

`deploy` runs these steps:

1. Copies `.env.example` to `.env` if `.env` is missing.
2. Stops if `WAZUH_HOST`, `WAZUH_USER` or `WAZUH_PASS` is empty or still a placeholder.
3. Adds `AUTH_SECRET_KEY` and `MCP_API_KEY` to `.env` when they are missing.
4. Builds with `--pull`, starts with `--wait`, and runs health checks.
5. Prints the API key and a `curl` command for `/auth/token`.

`install.sh` and `deploy-production.sh` are deprecated and target an old version. Use `docker compose` or `deploy.py`.

### Published image

Release builds are pushed to `ghcr.io/gensecaihq/wazuh-mcp-server`, tagged `<version>` (for example `4.3.0`), `<major>.<minor>` and `v<version>`. Builds from `main` are also tagged `latest`. The image runs as UID 1000 and defaults to `ENVIRONMENT=production`.

## Service management

```bash
docker compose ps
docker compose logs -f --timestamps wazuh-main-server
docker compose up -d                   # apply .env or compose.yml changes (recreates the container)
docker compose restart wazuh-main-server   # restart with the SAME environment
docker compose down --timeout 30
```

`docker compose restart` does not re-read `.env`. Use `docker compose up -d` after any configuration change.

On `SIGTERM` the server waits up to 20 seconds for open connections, such as SSE streams, before shutting down. `compose.yml` does not set `stop_grace_period`, so Docker's default of 10 seconds applies. Pass `--timeout 30` to `docker compose down` or `stop` to allow a full graceful shutdown.

### Running more than one instance

`compose.yml` is single-instance: it has a fixed `container_name` and host port, so `docker compose up --scale` does not work with it. For several instances behind a load balancer:

- Set the same `AUTH_SECRET_KEY` and API keys on every instance. Bearer tokens then validate on any of them.
- Set a shared `REDIS_URL` so legacy MCP sessions are visible to every instance.
- Use sticky sessions (or a single instance) if you rely on OAuth or on rate limits. OAuth authorization codes, refresh tokens, the revocation list, identity-provider logins in progress and rate-limit counters are held in each process.
- `MAX_SESSIONS` and `MAX_SESSIONS_PER_PRINCIPAL` bound each instance's in-memory store. With `REDIS_URL` they are not applied; Redis key TTLs bound the store instead.
- Set `TRUSTED_PROXIES` to the load balancer's address so rate limiting sees real client IPs.

## Health and readiness

| Endpoint | Purpose | Status codes |
|----------|---------|--------------|
| `GET /health` | Liveness. Does not check Wazuh, the Indexer or Redis | `200` while the process is serving |
| `GET /ready` | Readiness. Checks Manager reachability, Indexer cluster health (if configured), memory against `MAX_MEMORY_MB`, and the session store | `200` when all checks pass, otherwise `503` |

```bash
curl -s http://localhost:3000/health | jq .status
# "healthy"

curl -s http://localhost:3000/ready | jq '{status, services}'
# {"status":"healthy","services":{"wazuh_manager":"healthy","wazuh_indexer":"healthy","memory":"healthy","mcp":"healthy"}}
```

How to read `/ready`:

- **Status:** `status` is `healthy` or `degraded`. It is `unhealthy` if the check itself failed, for example while Redis is unreachable.
- **Manager:** `wazuh_manager` is `healthy` or `unhealthy`. When unhealthy, `wazuh_manager_reason` gives the category (`tls_verification_failed`, `authentication_failed`, `unreachable` or `error`); the full message is logged once each time it changes.
- **Indexer:** `wazuh_indexer` is `healthy` (cluster green or yellow), `degraded` (red), `unhealthy` or `not_configured`.
- **Memory:** `memory` is `healthy` or `over_limit`.
- **Other fields:** the response also reports the auth mode, the configured clusters and session counts.
- **Caching:** results are cached for 5 seconds, so frequent probes do not add load on the Manager.

Use `/health` for container liveness and `/ready` for load-balancer or orchestrator readiness. A Wazuh outage should take the instance out of rotation, not restart it. The `compose.yml` healthcheck probes `/health` every 15 seconds, with a 45-second start period and 3 retries.

```bash
docker inspect wazuh-main-server --format '{{.State.Health.Status}}'
```

`/health`, `/ready` and `/metrics` need no authentication, are not rate limited, and keep answering when memory is over the limit.

## Metrics

`GET /metrics` serves Prometheus text format. `compose.yml` labels the container with `monitoring.prometheus.scrape=true`, port `3000` and path `/metrics`.

| Metric | Type | Labels |
|--------|------|--------|
| `wazuh_mcp_requests_total` | counter | `method`, `endpoint`, `status_code` |
| `wazuh_mcp_request_duration_seconds` | histogram | `method`, `endpoint` |
| `wazuh_mcp_active_connections` | gauge | |
| `wazuh_mcp_auth_attempts_total` | counter | `result` |
| `wazuh_mcp_tool_executions_total` | counter | `tool_name`, `status` |
| `wazuh_mcp_tool_duration_seconds` | histogram | `tool_name` |
| `wazuh_mcp_rate_limit_hits_total` | counter | `endpoint` |
| `wazuh_mcp_errors_total` | counter | `error_type`, `component` |
| `wazuh_mcp_sessions_created_total`, `wazuh_mcp_sessions_expired_total` | counter | |
| `wazuh_mcp_cache_hits_total`, `wazuh_mcp_cache_misses_total` | counter | `cache_type` |
| `wazuh_mcp_memory_usage_bytes`, `wazuh_mcp_cpu_usage_percent` | gauge | |
| `wazuh_mcp_server_info` | info | |

Series with labels appear only after the first matching event.

```bash
curl -s http://localhost:3000/metrics | grep -E '^wazuh_mcp_(requests_total|active_connections|memory_usage_bytes)'
```

## Logs

The server logs to stderr, which Docker collects. `compose.yml` rotates the `json-file` log at 10 MB and keeps 3 files.

- **Text format** (default): `<time> - <logger> - <level> - [<correlation id>] <message>`.
- **JSON format:** set `LOG_FORMAT=json` for one JSON object per line, for log shippers.
- **Correlation IDs:** each request gets an ID, returned in the `X-Correlation-ID` response header. A client can supply its own in `X-Correlation-ID` or `X-Request-ID`.
- **Redaction:** credentials and tokens are redacted from log output.

```bash
docker compose logs --tail=100 wazuh-main-server
docker compose logs --since=24h wazuh-main-server > server.log
docker compose logs wazuh-main-server | grep -E 'ERROR|WARNING'
```

### Audit trail

Each call to a `wazuh:write` tool writes two `WARNING` records on the `wazuh_mcp_server.audit` logger:

```text
AUDIT: tool=<name> client=<principal> session=<id> args={...}
AUDIT_OUTCOME: tool=<name> outcome=success|failure principal=<principal> session=<id> duration_ms=<n> args={...}
```

```bash
docker compose logs wazuh-main-server | grep -E 'AUDIT(_OUTCOME)?:'
```

The principal is `env-<hash>` for `MCP_API_KEY`, the entry's `id` for `API_KEYS`, and `oauth:<client>:<subject>` for OAuth, where the subject is the API key id or, with an identity provider, the user identity chosen by `OAUTH_IDP_SUBJECT_CLAIM`. Forward these records to your SIEM if you need to keep them. Container logs are rotated.

## Maintenance

### Updating

```bash
git pull
docker compose build --pull
docker compose up -d
```

`wazuh-main-server` is a locally built image, so `docker compose pull` does not apply to it. Read [UPGRADING.md](../UPGRADING.md) before moving between versions.

### Rotating credentials

| What changes | Effect | Action |
|--------------|--------|--------|
| `MCP_API_KEY`, or a key removed from `API_KEYS` | JWTs minted from that key are rejected (`401 Invalid or expired token`) | Clients call `POST /auth/token` with the new key |
| `AUTH_SECRET_KEY` | Every bearer JWT and OAuth token is rejected, and every `API_KEYS` `key_hash` stops matching | Recompute `API_KEYS` hashes, then re-issue tokens and re-authorize OAuth clients |
| `WAZUH_PASS` / `WAZUH_INDEXER_PASS` | None until the container is recreated | `docker compose up -d` |

Apply each change with `docker compose up -d`.

### Backups

The deployment's state is its configuration. Sessions and OAuth tokens are temporary, and the container keeps no data volume.

```bash
tar -czf wazuh-mcp-config-$(date +%Y%m%d).tar.gz .env config/
```

`.env` holds secrets. Store the archive accordingly.

### Image scanning

CI scans each image with Trivy before publishing it and blocks the push on fixable HIGH or CRITICAL findings. To scan a local build:

```bash
trivy image wazuh-main-server:${VERSION:-4.3.0}
```

## Endpoint reference

| Endpoint | Methods | Auth | Description |
|----------|---------|------|-------------|
| `/mcp` | `POST`, `GET`, `DELETE` | yes | Streamable HTTP MCP endpoint. Serves MCP 2026-07-28 statelessly, and 2024-11-05 through 2025-11-25 with `initialize` and `MCP-Session-Id`. `DELETE` ends a session (`204`, or `404` if unknown) |
| `/` | `POST`, `GET` | yes | Same JSON-RPC handling as `/mcp`, kept for older clients |
| `/auth/token` | `POST` | API key in body | Exchanges `{"api_key": "wazuh_..."}` for a JWT (bearer mode) |
| `/health` | `GET` | no | Liveness |
| `/ready` | `GET` | no | Readiness (cached 5 s) |
| `/metrics` | `GET` | no | Prometheus metrics |
| `/docs`, `/redoc`, `/openapi.json` | `GET` | no | OpenAPI documentation |
| `/sse` | `GET`, `POST` | no | Always `410 Gone`. The legacy HTTP+SSE transport was removed; use `/mcp` |
| `/.well-known/oauth-authorization-server` | `GET` | no | RFC 8414 metadata (`404` unless `AUTH_MODE=oauth`) |
| `/.well-known/oauth-protected-resource` | `GET` | no | RFC 9728 metadata (`404` unless `AUTH_MODE=oauth`) |
| `/oauth/authorize` | `GET`, `POST` | API key or IdP sign-in | Authorization endpoint (OAuth mode only). With `OAUTH_IDP_ISSUER` set, `GET` redirects to the identity provider |
| `/oauth/callback` | `GET` | IdP | Return from the identity provider (OAuth mode with `OAUTH_IDP_ISSUER` only; `404` otherwise) |
| `/oauth/token` | `POST` | PKCE | Code exchange and refresh (OAuth mode only) |
| `/oauth/revoke` | `POST` | | Token revocation, RFC 7009 (OAuth mode only) |
| `/oauth/register` | `POST` | | Dynamic Client Registration. Returns `400` unless `OAUTH_ENABLE_DCR=true` (OAuth mode only) |

### Manual session with curl

```bash
BASE=http://localhost:3000
TOKEN=$(curl -s -X POST $BASE/auth/token -H 'Content-Type: application/json' \
  -d '{"api_key": "wazuh_..."}' | jq -r .access_token)
H=(-H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream')

# initialize returns the session id in the MCP-Session-Id response header
SID=$(curl -s -D - -o /dev/null -X POST $BASE/mcp "${H[@]}" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}' \
  | awk -F': ' 'tolower($1)=="mcp-session-id"{print $2}' | tr -d '\r')

curl -s -X POST $BASE/mcp "${H[@]}" -H "MCP-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}'           # 202
curl -s -X POST $BASE/mcp "${H[@]}" -H "MCP-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' | jq '.result.tools | length'
curl -s -X DELETE $BASE/mcp -H "Authorization: Bearer $TOKEN" -H "MCP-Session-Id: $SID"   # 204
```

`tools/list` returns only the tools the token's scopes allow: 41 for a read-only key, 55 with `wazuh:write`, fewer if toolsets are restricted.

## Capacity and tuning

| Setting | Where | Default | Notes |
|---------|-------|---------|-------|
| CPU and memory limit | `compose.yml` `deploy.resources` | 1 CPU, 512 MB | Raise the memory limit and `MAX_MEMORY_MB` together. With both at 512, the container can be OOM-killed before the server's own 503 guard triggers |
| `MAX_MEMORY_MB` | `.env` | `512` | Above this RSS, non-probe requests get `503 Server overloaded` |
| `MAX_CONNECTIONS` | `.env` | `10` | Concurrent Manager requests for the environment-configured cluster (1–100); `clusters.json` entries use 10 |
| `REQUEST_TIMEOUT_SECONDS` | `.env` | `30` | Manager and Indexer timeout (1–300); `clusters.json` entries use `request_timeout_seconds` |
| `MAX_ALERTS_PER_QUERY` | `.env` | `1000` | Largest `limit` for `get_wazuh_alerts` and `search_security_events` (1–10000) |
| `MAX_SESSIONS` / `MAX_SESSIONS_PER_PRINCIPAL` | `.env` | `1000` / `100` | In-memory session caps; the least recently active sessions are evicted beyond them |
| `MAX_TOOL_RESPONSE_CHARS` | `.env` | `1000000` | Cap on a single tool result |
| `RATE_LIMIT_REQUESTS` / `RATE_LIMIT_WINDOW` | `.env` | `100` / `60` | Sliding-window limit: per principal and client IP on `/mcp` and `/`, per IP on other routes |

---

[Back to README](../README.md) · [Configuration](configuration.md) · [Troubleshooting](TROUBLESHOOTING.md)
