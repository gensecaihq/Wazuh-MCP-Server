# Troubleshooting

Each entry lists the message you see, what causes it, and the fix. Messages are quoted exactly as the server produces them. For variable details see the [Configuration Reference](configuration.md).

## First checks

```bash
docker compose ps                                   # is the container running / healthy?
docker compose logs --tail=100 wazuh-main-server    # startup errors are logged here
curl -s http://localhost:3000/health                # liveness
curl -s http://localhost:3000/ready | jq .services  # Manager / Indexer / memory status
```

For more detail, set `LOG_LEVEL=DEBUG` in `.env` and run `docker compose up -d`. `docker compose restart` does not pick up `.env` changes.

The image includes `curl` and `jq`. Use them to test reachability from inside the container's network:

```bash
docker compose exec wazuh-main-server curl -sk -o /dev/null -w '%{http_code}\n' "https://<wazuh-host>:55000/"
# any HTTP status means the Manager is reachable; 000 means no connection
```

## The server does not start

If the process exits during startup, the container restarts in a loop. `docker compose logs` shows a line such as `Server error: <message>`, or a Python traceback ending in `ConfigurationError: <message>` (followed by `Application startup failed. Exiting.` when the check runs in the startup hook).

| Message | Cause | Fix |
|---------|-------|-----|
| `Required Wazuh Manager settings are not set: WAZUH_HOST, WAZUH_USER, WAZUH_PASS` | The named variables are empty or unset. With Compose, `.env` is missing them or the container was not recreated after editing | Set them in `.env`, then `docker compose up -d` |
| `AUTH_SECRET_KEY is required when ENVIRONMENT=production and AUTH_MODE is not 'none'.` | `compose.yml` and the Docker image run with `ENVIRONMENT=production`, and no signing key is set | Add `AUTH_SECRET_KEY=$(openssl rand -hex 32)` to `.env`, or run `python deploy.py`, which adds one. Then `docker compose up -d` |
| `AUTH_SECRET_KEY is set to a placeholder or is too weak for production (need a random value of at least 32 characters; got N).` | The key is shorter than 32 characters, or contains `change_me`, `changeme`, `your-secret` or `example`, or starts with `<` | Replace it with `openssl rand -hex 32` |
| `ENVIRONMENT must be 'development' or 'production', got '...'` | Unsupported value | Use `development`, `dev`, `production` or `prod` |
| `AUTH_MODE must be one of bearer, oauth, none; got '...'` | Typo | Use `bearer`, `oauth` or `none` |
| `<VAR> must be a boolean (true/false/1/0/yes/no/on/off), got '...'` | A strict boolean such as `WAZUH_VERIFY_SSL` has another value | Use one of the listed values |
| `<VAR> must be positive, got N` / `<VAR> must be <= MAX, got N` / `<VAR> must be a valid integer, got '...'` | Out-of-range numeric setting | See the ranges in [Configuration](configuration.md) |
| `MCP_PORT must be between 1 and 65535, got N` (also `WAZUH_PORT`, `WAZUH_INDEXER_PORT`) | Invalid port | Fix the value |
| `MAX_MEMORY_MB must be at least 64, got N` | The ceiling is below the server's idle footprint | Use 64 or more |
| `WAZUH_TOOLSETS: unknown toolset(s) ... Valid: all, agents, alerts, analysis, compliance, response, system, vulnerabilities, web_search` | Unknown toolset name | Use a listed name |
| `WAZUH_DISABLED_TOOLS: unknown tool(s) ...` | Unknown tool name | Check names with `tools/list` |
| `1 validation error for APIKey` | An `API_KEYS` entry is missing a required field (`id`, `name`, `key_hash`, `created_at`) | See [Multiple API keys](configuration.md#multiple-api-keys) |
| `Invalid JSON in clusters file ...`, `cluster '<id>' is missing required field '...'`, `clusters file references unset environment variable '...'` | `config/clusters.json` exists but is invalid | Fix the file (see [Multi-Cluster Guide](MULTI_CLUSTER.md)) or remove it |
| `WAZUH_CA_BUNDLE points to a file that does not exist: <path>` | The path is wrong, or the file is not mounted into the container | Mount the directory (`compose.yml` has a commented `./certs:/app/certs:ro` line) and use the in-container path |
| `cluster '<id>': ca_bundle file does not exist: <path>` | Same, for a `clusters.json` entry (or the global `WAZUH_CA_BUNDLE` it inherits) | Fix the path or the mount |
| `OAUTH_IDP_ISSUER must be an https:// URL`, `OAUTH_IDP_CLIENT_ID is required when OAUTH_IDP_ISSUER is set` | Incomplete identity-provider settings. They are checked whenever `OAUTH_IDP_ISSUER` is set, whatever `AUTH_MODE` is | Complete them, or unset `OAUTH_IDP_ISSUER` |
| `OAUTH_IDP_ISSUER is a multi-tenant issuer; set OAUTH_IDP_ALLOWED_TENANTS or use the tenant-specific issuer URL` | An Entra `/common/`, `/organizations/` or `/consumers/` issuer without a tenant allow-list | Use `https://login.microsoftonline.com/<tenant-id>/v2.0`, or set `OAUTH_IDP_ALLOWED_TENANTS` |
| `OAUTH_IDP_ISSUER is Google, which admits any Google account; set OAUTH_IDP_ALLOWED_DOMAINS ...` | Google issuer with no domain or user allow-list | Set `OAUTH_IDP_ALLOWED_DOMAINS` to your Workspace domain, or `OAUTH_IDP_ALLOWED_USERS` |
| `OAUTH_IDP_GROUP_SCOPE_MAP must be a JSON object`, `OAUTH_IDP_GROUP_SCOPE_MAP['<group>'] grants no known scope`, `OAUTH_IDP_DEFAULT_SCOPE contains unknown scope(s): ...` | Malformed scope mapping | Use a JSON object of strings with the scopes `wazuh:read` and `wazuh:write` |
| `Invalid active-response command name: '...'` | `WAZUH_AR_*_UNDO_COMMAND` contains characters other than letters, digits, `_` and `-` | Use the plain command name, for example `!firewall-undrop` |

`docker compose` itself fails with `env file .../.env not found` when `.env` is missing. Fix it with `cp .env.example .env`.

## Cannot reach the server

**Symptom:** `curl: (7) Failed to connect` or `Connection refused`.

- **Remote hosts cannot connect.** By default `compose.yml` publishes the port on `127.0.0.1` only (`MCP_BIND`), for a reverse proxy on the same host. Put a TLS-terminating proxy in front, or set `MCP_BIND=0.0.0.0` on a trusted network, then run `docker compose up -d`.
- **Port in use.** Another process holds the host port: `docker compose up` reports `port is already allocated`. Pick a different host port with `MCP_PORT` in `.env`; the container always listens on 3000.
- **Container not running or restarting.** See [The server does not start](#the-server-does-not-start).
- **HTTPS to the server fails.** The server speaks plain HTTP only, so `https://host:3000` does not work. Terminate TLS at a reverse proxy.

## Authentication errors

| Status and message | Cause | Fix |
|--------------------|-------|-----|
| `401 {"detail":"Authorization header required"}` | No `Authorization` header (bearer or OAuth mode) | Send `Authorization: Bearer <token>` |
| `401 {"detail":"Invalid or expired token"}` | The JWT has expired (`TOKEN_LIFETIME_HOURS`, default 24), its API key was changed or removed, `AUTH_SECRET_KEY` changed, or the token was minted before the upgrade that bound tokens to keys | Get a new token from `POST /auth/token` |
| `401 {"detail":"Invalid API key format"}` from `/auth/token` | The key does not start with `wazuh_` | Use the `MCP_API_KEY` value |
| `401 {"detail":"Invalid API key"}` from `/auth/token` | The key is unknown | Check `grep ^MCP_API_KEY= .env`. If the log shows `MCP_API_KEY format invalid. Expected format: wazuh_<43-char-base64>.`, the server ignored the configured key: generate a new one with `python -c "import secrets; print('wazuh_' + secrets.token_urlsafe(32))"` |
| `400 {"detail":"API key required"}` | The body has no `api_key` | Send `{"api_key": "wazuh_..."}` with `Content-Type: application/json` |
| Log: `No MCP_API_KEY configured in production — generated a temporary READ-ONLY default key.` | No key is configured. In production the generated key is never shown | Set `MCP_API_KEY` (and `MCP_API_KEY_SCOPES`) or `API_KEYS` |

Tokens survive restarts and work across replicas only if `AUTH_SECRET_KEY` is set and identical everywhere. Outside production, an unset key is regenerated on each start, which invalidates every token.

### OAuth

| Symptom | Cause | Fix |
|---------|-------|-----|
| `401 {"detail":"Invalid or expired OAuth token"}` on `/mcp` | The access token expired (`OAUTH_ACCESS_TOKEN_TTL`), was revoked, `AUTH_SECRET_KEY` changed (or is unset and was regenerated at restart), or the API key the user signed in with was removed | Let the client refresh or re-authorize |
| `404 {"detail":"OAuth not enabled. Set AUTH_MODE=oauth to enable."}` on `/.well-known/...` | The server is in bearer or authless mode | Set `AUTH_MODE=oauth` and run `docker compose up -d` |
| The sign-in page says `That API key isn't valid.` | The pasted key is not configured | Use a key from `MCP_API_KEY` or `API_KEYS`. OAuth sign-in needs at least one configured key |
| The sign-in page says `Your API key has none of the requested scopes.` | The key's scopes do not overlap with the client's request | Grant the key `wazuh:read` (and `wazuh:write` if needed) |
| The client is redirected to the wrong host, or discovery metadata shows an internal URL | The issuer is derived from the request, and the proxy is not trusted | Set `OAUTH_ISSUER_URL` to the public URL, or add the proxy to `TRUSTED_PROXIES` |
| `400 "Dynamic client registration is disabled"` from `/oauth/register` | `OAUTH_ENABLE_DCR` is off, which is the default | Enable it if your client requires DCR |
| Client redirected back with `error=temporarily_unavailable`; log: `IdP unavailable during authorize: OIDC discovery failed: ...` | The server cannot fetch `<OAUTH_IDP_ISSUER>/.well-known/openid-configuration`, or the document's issuer does not match `OAUTH_IDP_ISSUER` | Check outbound HTTPS from the container to the provider and the exact issuer URL (Entra: `.../<tenant-id>/v2.0`) |
| `error_description=Login could not be verified with the identity provider`; log: `IdP login failed for client <id>: ...` | Code exchange or ID-token check failed (wrong client secret, redirect URI not registered, `aud`/`iss`/`nonce` mismatch) | Register `<OAUTH_ISSUER_URL>/oauth/callback` at the provider and check `OAUTH_IDP_CLIENT_ID` / `OAUTH_IDP_CLIENT_SECRET` |
| `error_description=This account is not authorized to use this server`; log: `IdP login denied by policy (<reason>)` | The user failed an allow-list (`tenant not allowed`, `domain not allowed`, `user not allowed`) or, with `OAUTH_IDP_DEFAULT_SCOPE` empty, is in no mapped group (`user matches no scope mapping`) | Adjust `OAUTH_IDP_ALLOWED_*` or `OAUTH_IDP_GROUP_SCOPE_MAP` |
| `400 "Unknown or expired login state"` on `/oauth/callback` | The user took longer than `OAUTH_IDP_LOGIN_TTL`, the callback reached a different instance, or the server restarted during sign-in | Retry the sign-in. With several instances, route `/oauth/*` to one |

## MCP endpoint errors

| Status and message | Cause | Fix |
|--------------------|-------|-----|
| `403 {"detail":"Origin not allowed: <origin>"}` | The request carried an `Origin` header that is not listed in `ALLOWED_ORIGINS` (exact match, no wildcards) | Add the exact origin (scheme, host, port) to `ALLOWED_ORIGINS` |
| `404 {"detail":"Session not found. Please start a new session with InitializeRequest."}` | The `MCP-Session-Id` is unknown. In-memory sessions are lost on restart, are not shared between instances, and are evicted when the store reaches `MAX_SESSIONS` or the key reaches `MAX_SESSIONS_PER_PRINCIPAL` (log: `Session store at MAX_SESSIONS=<n>; evicted least recently active sessions`) | Send `initialize` again. With several instances, set `REDIS_URL`. If eviction is frequent, raise the caps |
| `404 {"detail":"Session expired. Please start a new session with InitializeRequest."}` | The session was idle for more than 30 minutes | Send `initialize` again |
| `503 {"error":"Session store unavailable; retry shortly"}` with `Retry-After: 5` | `REDIS_URL` is set but Redis is unreachable. `/ready` also returns 503 | Restore Redis connectivity. The server reconnects without a restart |
| `410` from `/sse` | The legacy HTTP+SSE transport was removed | Point the client at `/mcp` |
| `429 {"detail":"Rate limit exceeded"}` | More than `RATE_LIMIT_REQUESTS` (default 100) requests in `RATE_LIMIT_WINDOW` seconds (default 60) from one principal and IP on `/mcp` or `/`, or from one IP on other routes. Repeated failed authentication also ends in `429` | Honour `Retry-After`, or raise the limits. Behind a proxy, set `TRUSTED_PROXIES`, or every client shares the proxy's IP |
| `503 {"detail":"Server overloaded"}` | Process memory is above `MAX_MEMORY_MB`. `/ready` shows `memory: over_limit` | Narrow large queries, or raise `MAX_MEMORY_MB` and the container memory limit together |

To check the endpoint by hand:

```bash
# Without a token (bearer mode): expect 401
curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:3000/mcp \
  -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"ping"}'

# With a token: expect 200 and an InitializeResult, plus an MCP-Session-Id header
curl -s -i -X POST http://localhost:3000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"curl","version":"1"}}}'
```

[Operations](OPERATIONS.md#manual-session-with-curl) has a complete session example.

## Tool calls fail with connection errors

Tool failures come back as `isError` results, which the model reads, not as HTTP errors.

| Tool result | Cause | Fix |
|-------------|-------|-----|
| `Connection failed: TLS certificate verification failed for <host>. The stock Wazuh API certificate ...` | Manager certificate verification is on (the default) and the certificate is not trusted or does not name `WAZUH_HOST`. The stock certificate (`CN=wazuh.com`, no subjectAltName) always fails | Reissue the certificate with a matching subjectAltName and set `WAZUH_CA_BUNDLE`, or set `WAZUH_ALLOW_SELF_SIGNED=true`. See [Manager TLS](configuration.md#manager-tls) |
| `... CA cert does not include key usage extension` | Python 3.13's strict X.509 checks: the CA in `WAZUH_CA_BUNDLE` lacks `keyUsage` | Reissue the CA with `keyUsage=critical,keyCertSign,cRLSign` |
| `Connection failed: Cannot connect to Wazuh server at <host>:<port>. Check Wazuh server connectivity and try again.` | The Manager is unreachable: wrong `WAZUH_HOST`/`WAZUH_PORT`, a firewall, or DNS | Test from the container (see [First checks](#first-checks)) |
| `Connection failed: Connection timeout to Wazuh server at <host>. ...` | The Manager did not answer within `REQUEST_TIMEOUT_SECONDS` | Check the network path and the Manager's load |
| `Tool execution failed: Invalid Wazuh credentials. Check WAZUH_USER and WAZUH_PASS` | The Manager rejected the login (HTTP 401) | Check the credentials with the command below |
| `Tool execution failed: Wazuh user does not have sufficient permissions` | The Manager returned 403 at login | Give the API user the Wazuh RBAC roles it needs |
| Result contains `Service temporarily unavailable - circuit breaker open` | Five connection, timeout or 5xx failures in a row opened the circuit breaker for that cluster | Fix the Manager connection. The breaker lets a trial request through after 60 s |

```bash
# The login the server performs
curl -k -u "$WAZUH_USER:$WAZUH_PASS" -X POST "https://$WAZUH_HOST:55000/security/user/authenticate"
# Expect 200 and {"data":{"token":"..."}}
```

### Indexer (alerts, vulnerabilities, compliance evidence)

| Tool result | Cause | Fix |
|-------------|-------|-----|
| `Wazuh Indexer not configured. Alerts are stored in the Wazuh Indexer and require WAZUH_INDEXER_HOST to be set.` | No Indexer is configured. Alert and vulnerability data come from the Indexer on Wazuh 4.8 and later | Set `WAZUH_INDEXER_HOST`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS` |
| `Wazuh Indexer authentication failed (HTTP 401). Check WAZUH_INDEXER_USER / WAZUH_INDEXER_PASS.` (or 403) | Wrong credentials, or a user without read access to `wazuh-alerts-*` / `wazuh-states-vulnerabilities-*` | Fix the credentials or the Indexer role |
| `Tool execution failed: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate ...` | `WAZUH_INDEXER_VERIFY_SSL=true` (the default) with a self-signed Indexer certificate, which is the stock Wazuh setup | Set `WAZUH_INDEXER_VERIFY_SSL=false`, or have the Indexer present a certificate the server trusts |
| `Tool execution failed: All connection attempts failed` (some tools: `Cannot connect to Wazuh Indexer at <host>:<port>`) | The Indexer is unreachable, the port is wrong, or the scheme is wrong | Check `WAZUH_INDEXER_HOST`/`WAZUH_INDEXER_PORT`. For a plain-HTTP node, set `WAZUH_INDEXER_SSL=false` |

```bash
curl -k -u "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASS" "https://$WAZUH_INDEXER_HOST:9200/_cluster/health"
```

`/ready` reports `wazuh_indexer: degraded` when the Indexer cluster is red, and `unhealthy` when it cannot be reached.

## Tool refusals

These refusals come from policy settings, not from faults.

| Tool result | Cause | Fix |
|-------------|-------|-----|
| `Insufficient permissions: tool '<name>' requires 'wazuh:write' scope. ...` | The token is read-only, which is the default | Grant `wazuh:write` (`MCP_API_KEY_SCOPES="wazuh:read wazuh:write"` or `API_KEYS` scopes), then mint a new token. In authless mode, set `AUTHLESS_ALLOW_WRITE=true` |
| `Tool '<name>' is disabled on this server (WAZUH_TOOLSETS / WAZUH_DISABLED_TOOLS).` | The tool is filtered out | Adjust `WAZUH_TOOLSETS` / `WAZUH_DISABLED_TOOLS` |
| `Tool '<name>' changes system state and requires explicit confirmation. Re-invoke with confirm=true only after a human operator has approved the exact target. ...` | `WAZUH_REQUIRE_ACTION_CONFIRMATION` is on, which is the default with `ENVIRONMENT=production` (the Docker image and `compose.yml`) | After a human has approved the action, call again with `confirm=true`. To turn the gate off, set `WAZUH_REQUIRE_ACTION_CONFIRMATION=false` |
| `Tool execution failed: Refusing to run '<name>' against agent 000 (the Wazuh manager itself) ...` | Host-level active response aimed at the Manager | Target the correct agent. Set `WAZUH_ALLOW_MANAGER_AR=true` only if this is intended |
| `Tool execution failed: Refusing to restart the Wazuh manager: this interrupts the whole SOC control plane. ...` | `wazuh_restart` with `target=manager` (or `000`) | Restart a specific agent, or set `WAZUH_ALLOW_MANAGER_AR=true` |
| `Tool execution failed: Refusing fleet-wide block (all_agents=true): blocking an IP on every agent at once is opt-in. ...` | `wazuh_block_ip` with `all_agents=true` | Pass an `agent_id`, or set `WAZUH_ALLOW_FLEET_AR=true` |
| `Tool execution failed: Refusing to block protected target <ip>: it is loopback, the Wazuh manager, or on the WAZUH_PROTECTED_IPS denylist. ...` | The IP is protected | Intended behaviour. Edit `WAZUH_PROTECTED_IPS` if the entry is wrong |
| `Tool execution failed: Use wazuh_firewall_drop to run !firewall-drop; the generic tool does not dispatch IP blocks.` (or `wazuh_host_deny` / `!host-deny`) | `wazuh_active_response` was asked to run an IP-blocking command | Use the named dedicated tool |
| `Invalid parameter 'file_path': is inside protected location <dir>. ...` | `wazuh_quarantine_file` target is under a built-in or `WAZUH_QUARANTINE_DENY_PREFIXES` directory | Intended behaviour. The built-in list cannot be overridden |
| `Invalid parameter 'file_path': is outside WAZUH_QUARANTINE_ALLOW_PREFIXES. ...` | An allow-list is configured and the path is not under it | Add the directory to `WAZUH_QUARANTINE_ALLOW_PREFIXES` |
| `Invalid parameter 'file_path': must be an absolute path. ...` | Relative quarantine path | Pass the full path |
| `Invalid parameter 'duration': per-call block durations are not supported ...` | A positive `duration` on a block tool; Wazuh ignores the timeout for API-triggered active response | Omit `duration`; remove the block later |
| `Tool execution failed: Cannot remove a firewall block through the Wazuh API: ...` (or `host-deny`) | No undo command is configured. Stock Wazuh cannot remove a block through the API | Deploy an undo active-response script and set `WAZUH_AR_FIREWALL_UNDO_COMMAND` / `WAZUH_AR_HOSTDENY_UNDO_COMMAND` |
| Text ends with `[Truncated: the result exceeded N characters. ...]` | The result is longer than `MAX_TOOL_RESPONSE_CHARS` | Use a smaller `limit`, a shorter time range, or `compact=true` |
| `search_external_context` returns `"enabled": false` | `YDC_API_KEY` is not set | Set it, or hide the tool with `WAZUH_DISABLED_TOOLS` |

Active-response tools report `execution_status: "dispatched"`: Wazuh accepted the command for delivery. To confirm the effect on the agent, use the matching `wazuh_check_*` tool.

## Client connection issues

- **The client cannot reach the server.** The MCP endpoint is `/mcp` (`/` also works; `/sse` returns 410), and the server itself speaks plain HTTP only. A client that requires HTTPS or runs outside your network needs a TLS-terminating reverse proxy in front of it. See [Claude Integration](CLAUDE_INTEGRATION.md) for client-specific setup.
- **The connector gets a 403 `Origin not allowed`.** Add the client's origin to `ALLOWED_ORIGINS`. Matching is exact.
- **Tools list is shorter than expected.** `tools/list` returns only what the token's scopes allow (41 read tools and 14 write tools) and what `WAZUH_TOOLSETS` / `WAZUH_DISABLED_TOOLS` leave enabled.

## Collecting information for a bug report

```bash
docker compose logs --since=1h wazuh-main-server > server.log   # credentials are redacted in logs
curl -s http://localhost:3000/ready > ready.json
curl -s http://localhost:3000/health | jq .version
```

Include the server version, Wazuh version, `AUTH_MODE`, and the exact error text. Open an issue at <https://github.com/gensecaihq/Wazuh-MCP-Server/issues>.

---

[Back to README](../README.md) · [Configuration](configuration.md) · [Operations](OPERATIONS.md)
