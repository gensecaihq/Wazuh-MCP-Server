# Configuration Reference

Every environment variable the server reads, with its default, validation and effect. [`.env.example`](../.env.example) is a ready-to-copy template using the same names.

## How configuration is loaded

- The server reads its settings from **process environment variables** only. It does not load a `.env` file on its own.
- **Docker Compose** passes `.env` to the container through `env_file`. `compose.yml` then overrides three values: `MCP_HOST=0.0.0.0`, `MCP_PORT=3000` and `ENVIRONMENT=production`. `compose.dev.yml` sets `ENVIRONMENT=development` and `LOG_LEVEL=DEBUG` instead.
- **The Docker image** defaults to `ENVIRONMENT=production`, `MCP_HOST=0.0.0.0`, `MCP_PORT=3000` and `LOG_LEVEL=INFO`. With `docker run --env-file .env`, values in `.env` replace these defaults, so pass `-e MCP_HOST=0.0.0.0 -e ENVIRONMENT=production` as the README shows.
- **Running from source** (`python -m wazuh_mcp_server`): export the variables yourself, for example `set -a; . ./.env; set +a`.
- In `.env`, quote values that contain spaces or JSON (`MCP_API_KEY_SCOPES="wazuh:read wazuh:write"`, `API_KEYS='[...]'`) so that both Compose and the shell read them intact. `docker run --env-file` keeps the quotes; the server strips one pair of matching surrounding quotes from `MCP_API_KEY_SCOPES`, `API_KEYS` and the `OAUTH_IDP_*` list, scope and map values. Do not put a trailing comment after an empty value (`VAR=  # note` sets `VAR` to the comment text under Compose).
- Settings are read once, at startup. After changing `.env`, recreate the container with `docker compose up -d`. `docker compose restart` keeps the environment the container was created with.

### Startup validation

Invalid values stop the server at startup: it logs the error and exits with a non-zero status. The checks cover port ranges, positive integers, `ENVIRONMENT`, `AUTH_MODE`, boolean spelling, toolset names, `MAX_MEMORY_MB`, `WAZUH_CA_BUNDLE`, the active-response undo command names, the `OAUTH_IDP_*` settings, the clusters file and, in production, `AUTH_SECRET_KEY`. Each table below lists the checks that apply to that variable.

`WAZUH_HOST`, `WAZUH_USER` and `WAZUH_PASS` must be non-empty: if any is missing, startup fails with `Required Wazuh Manager settings are not set: <names>`. Whether the Manager is reachable and the credentials are valid is not checked at startup; a wrong host or password shows up on the first tool call (see [Troubleshooting](TROUBLESHOOTING.md#tool-calls-fail-with-connection-errors)).

### Boolean values

There are two kinds of boolean variable:

- **Strict booleans** (marked *strict* below) accept `1`, `true`, `yes`, `y`, `on` and `0`, `false`, `no`, `n`, `off`, in any case. Any other value fails startup. An empty value (`VAR=`) means `false`. The default applies only when the variable is unset.
- **Opt-in flags** (marked *opt-in*) are enabled only by `true`, `1` or `yes`, in any case. Any other value, including an empty one, leaves them off.

## Wazuh Manager

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_HOST` | *(none)* | **Required.** Manager hostname or IP. Any `http://`/`https://` prefix and trailing `/` are removed. The Manager API is always called over HTTPS |
| `WAZUH_USER` | *(none)* | **Required.** Manager API user |
| `WAZUH_PASS` | *(none)* | **Required.** Manager API password |
| `WAZUH_PORT` | `55000` | Manager API port (1–65535) |
| `WAZUH_VERIFY_SSL` | `true` | *Strict.* Verify the Manager's TLS certificate |
| `WAZUH_ALLOW_SELF_SIGNED` | `false` | *Strict.* `true` disables Manager certificate verification (needed for the stock self-signed certificate unless you reissue it; see [Manager TLS](#manager-tls)). Applies only to the Manager configured here, not to the Indexer or to `clusters.json` entries |
| `WAZUH_CA_BUNDLE` | *(none)* | PEM file of the CA(s) to trust for the Manager and Indexer instead of the system store. Startup fails if the file does not exist. Not used for a connection whose verification is off; a warning is logged when that is the Manager. Also the default `ca_bundle` for [clusters.json](MULTI_CLUSTER.md#tls) entries |
| `REQUEST_TIMEOUT_SECONDS` | `30` | Timeout for Manager and Indexer requests (1–300). `clusters.json` entries use their own `request_timeout_seconds` |
| `MAX_CONNECTIONS` | `10` | Maximum concurrent Manager requests, and the Manager connection pool size (1–100). `clusters.json` entries always use 10 |
| `MAX_ALERTS_PER_QUERY` | `1000` | Largest `limit` accepted by `get_wazuh_alerts` and `search_security_events` (1–10000); also advertised as the schema maximum. Other tools keep their own caps |

Manager certificate verification is on unless `WAZUH_VERIFY_SSL=false` or `WAZUH_ALLOW_SELF_SIGNED=true`.

### Manager TLS

The Manager certificate is verified by default. How to satisfy that depends on the certificate:

- **Stock install.** Wazuh generates `<WAZUH_PATH>/api/configuration/ssl/server.crt` (default `/var/ossec/...`) self-signed for `CN=wazuh.com` with no subjectAltName. Python matches hostnames only against the subjectAltName, so this certificate cannot be verified for any `WAZUH_HOST`, even if you pin it as the CA bundle. Either reissue it (next point) or set `WAZUH_ALLOW_SELF_SIGNED=true` to connect without verification, which is how earlier versions behaved.
- **Reissued certificate.** Issue a server certificate whose subjectAltName matches `WAZUH_HOST` (DNS name or IP), configure it in the Manager's `api.yaml` (`https.cert` / `https.key`), and point `WAZUH_CA_BUNDLE` at the PEM of the CA that signed it.
- **Publicly trusted certificate.** Nothing to set; the system trust store is used.

`WAZUH_CA_BUNDLE` replaces the system trust store for both the Manager and the Indexer. If they are signed by different CAs (for example your CA and the Indexer's `root-ca.pem` from `wazuh-certs-tool`), concatenate both PEM files into one bundle.

The container runs Python 3.13, which applies strict X.509 checks: a CA certificate needs a `keyUsage` extension with `keyCertSign`, and server certificates need a subjectAltName. A CA made without `keyUsage` fails with `CA cert does not include key usage extension`.

When verification fails, the first tool call that reaches the Manager returns `Connection failed: TLS certificate verification failed for <host>.` followed by these options. The server logs a startup warning (an error in production) whenever Manager verification is disabled.

Entries in `clusters.json` have their own `verify_ssl`, `indexer_verify_ssl` and `ca_bundle` fields; see [Multi-Cluster TLS](MULTI_CLUSTER.md#tls).

## Wazuh Indexer

The Indexer is required for alert search, alert aggregation, vulnerability tools and alert-backed compliance checks. Wazuh 4.8 removed the Manager's `/alerts` and vulnerability endpoints. When the Indexer is not configured, these tools return a "Wazuh Indexer not configured" error.

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_INDEXER_HOST` | *(none)* | Indexer hostname or IP. An `http://` prefix selects plain HTTP unless `WAZUH_INDEXER_SSL` is set |
| `WAZUH_INDEXER_PORT` | `9200` | Indexer port (1–65535) |
| `WAZUH_INDEXER_USER` | *(none)* | Indexer user |
| `WAZUH_INDEXER_PASS` | *(none)* | Indexer password |
| `WAZUH_INDEXER_SSL` | `true` | *Strict.* Use HTTPS. When unset, the scheme comes from the host prefix: HTTPS unless the host starts with `http://` |
| `WAZUH_INDEXER_VERIFY_SSL` | `true` | *Strict.* Verify the Indexer's TLS certificate. Stock Indexer certificates are signed by the `root-ca.pem` that `wazuh-certs-tool` generates, which is not in the system store: add it to `WAZUH_CA_BUNDLE`, or set this to `false` to skip verification. `WAZUH_ALLOW_SELF_SIGNED` does not affect the Indexer |

## Server

| Variable | Default | Description |
|----------|---------|-------------|
| `ENVIRONMENT` | `development` (image: `production`) | `development`/`dev` or `production`/`prod`. Any other value fails startup. See [Production requirements](#production-requirements) |
| `MCP_HOST` | `127.0.0.1` (`0.0.0.0` in the Docker image) | Bind address. Pinned to `0.0.0.0` inside the Compose container |
| `MCP_PORT` | `3000` | Listen port (1–65535). Plain HTTP only; terminate TLS at a reverse proxy. Pinned to `3000` inside the Compose container |
| `LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`. `WARN` is accepted as `WARNING`. Unrecognised values fall back to `INFO` |
| `LOG_FORMAT` | `text` | `json` writes one JSON object per line, including the request correlation ID and any structured fields. Any other value selects text |
| `MAX_MEMORY_MB` | `512` | Memory ceiling in MiB (minimum 64). Once the process RSS exceeds it, every request except `/health`, `/ready` and `/metrics` gets `503 Server overloaded`, and `/ready` reports `memory: over_limit`. Memory is sampled at most every 30 s |
| `WEB_CONCURRENCY`, `UVICORN_WORKERS`, `GUNICORN_WORKERS` | *(none)* | Not used to start workers. The server always runs a single process. A value above 1 only logs a warning, because token revocation, OAuth state and rate limits are held in each process |

## Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `AUTH_MODE` | `bearer` | `bearer`, `oauth` or `none`. Any other value fails startup |
| `AUTH_SECRET_KEY` | random per process (outside production) | Signs JWTs and hashes API keys. **Required when `ENVIRONMENT=production` and `AUTH_MODE` is not `none`.** In production it must be at least 32 characters and must not look like a placeholder (containing `change_me`, `changeme`, `your-secret` or `example`, or starting with `<`). Use the same value on every instance. Generate with `openssl rand -hex 32` |
| `TOKEN_LIFETIME_HOURS` | `24` | Lifetime of JWTs issued by `POST /auth/token` (1–8760) |
| `MCP_API_KEY` | *(none)* | A single API key: `wazuh_` followed by 43 URL-safe characters (49 in total). Generate with `python -c "import secrets; print('wazuh_' + secrets.token_urlsafe(32))"`. A value in any other format stops the server at startup |
| `MCP_API_KEY_SCOPES` | `wazuh:read` | Space-separated scopes for `MCP_API_KEY`: `wazuh:read`, `wazuh:write`. Unknown scopes are dropped. Add `wazuh:write` to allow the active-response tools |
| `API_KEYS` | *(none)* | JSON array of keys with individual scopes (see [Multiple API keys](#multiple-api-keys)). Ignored when `MCP_API_KEY` is set. Invalid JSON, or anything other than an array of objects, stops the server at startup |
| `AUTHLESS_ALLOW_WRITE` | `false` | *Opt-in.* With `AUTH_MODE=none`, grant `wazuh:write` to every caller. Otherwise authless callers are read-only |

When no key is configured, the server generates one for the life of the process:

- **Development:** the generated key is read-only. In bearer mode it is printed to stderr at startup; in OAuth mode it is not shown. For write access, set `MCP_API_KEY` and `MCP_API_KEY_SCOPES`.
- **Production:** the generated key is read-only and is never shown, so no client can use it. Set `MCP_API_KEY` or `API_KEYS`.

Bearer JWTs are bound to the API key they were minted from. Changing `MCP_API_KEY` or removing a key from `API_KEYS` invalidates that key's tokens: clients get `401 Invalid or expired token` and must call `POST /auth/token` again. Tokens remain valid across restarts and replicas as long as `AUTH_SECRET_KEY` and the key stay the same.

### Multiple API keys

Each `API_KEYS` entry is an object with these fields:

- `id` (required): the key's identity in audit logs and rate limits.
- `name` (required).
- `key_hash` (required): the HMAC-SHA256 of the key, using `AUTH_SECRET_KEY` as the HMAC key, hex-encoded.
- `created_at` (required): an ISO 8601 timestamp.
- `scopes`, `expires_at`, `active` and `metadata` (optional).

An entry with a missing required field stops the server at startup.

```bash
KEY=$(python -c "import secrets; print('wazuh_' + secrets.token_urlsafe(32))")
HASH=$(python -c "import hmac,hashlib,sys; print(hmac.new(sys.argv[1].encode(), sys.argv[2].encode(), hashlib.sha256).hexdigest())" "$AUTH_SECRET_KEY" "$KEY")
```

```env
API_KEYS='[{"id":"alice","name":"Alice","key_hash":"<HASH>","created_at":"2026-09-01T00:00:00Z","scopes":["wazuh:read"]}]'
```

Because the hash depends on `AUTH_SECRET_KEY`, changing the secret invalidates every `API_KEYS` entry.

### OAuth (`AUTH_MODE=oauth`)

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH_ISSUER_URL` | derived from the request | Public base URL of the server, for example `https://mcp.example.com`. When unset, the issuer is built from the request. `X-Forwarded-Proto`/`X-Forwarded-Host` are honoured only from loopback or a `TRUSTED_PROXIES` address. The server logs a warning when this is unset in production |
| `OAUTH_ENABLE_DCR` | `false` | *Strict.* Enables Dynamic Client Registration at `POST /oauth/register`. The endpoint is unauthenticated. When disabled it returns `400`. Refused at startup together with `OAUTH_IDP_ISSUER`: identity-provider sign-in has no consent step, so a self-registered client could receive other users' authorization codes. When 1000 clients are registered, clients without a live code or token are dropped, oldest first |
| `OAUTH_ACCESS_TOKEN_TTL` | `3600` | Access-token lifetime in seconds (positive integer) |
| `OAUTH_REFRESH_TOKEN_TTL` | `86400` | Refresh-token lifetime in seconds (positive integer) |
| `OAUTH_AUTHORIZATION_CODE_TTL` | `600` | Authorization-code lifetime in seconds (positive integer) |

How the OAuth flow works:

- **Sign-in:** users sign in on `/oauth/authorize` with a `wazuh_` API key, or at an OpenID Connect provider when `OAUTH_IDP_ISSUER` is set (below). Configure `MCP_API_KEY` or `API_KEYS` before enabling OAuth; without a key, nobody can sign in. The granted scopes are the intersection of the requested scopes, the client's registered scopes and the key's scopes.
- **Pre-registered client:** a public client, `claude-desktop`, is registered for the `https://claude.ai/api/mcp/auth_callback` and `https://claude.com/api/mcp/auth_callback` redirect URIs.
- **Token handling:** PKCE with `S256` is mandatory, authorization codes are single-use, and refresh tokens rotate on every use.

#### Sign-in through an OpenID Connect identity provider

Set `OAUTH_IDP_ISSUER` to have users authenticate at Entra ID, Google Workspace, Okta, Keycloak or another OIDC provider instead of the API-key sign-in page. `/oauth/authorize` then redirects to the provider; `/oauth/callback` verifies the ID token (RS256 signature from the provider's JWKS, `iss`, `aud`, `exp`, `nonce`), applies the allow-lists below and issues the MCP authorization code. Register `<OAUTH_ISSUER_URL>/oauth/callback` as the redirect URI at the provider.

| Variable | Default | Description |
|----------|---------|-------------|
| `OAUTH_IDP_ISSUER` | *(none)* | Provider issuer URL (`https://` only), e.g. `https://login.microsoftonline.com/<tenant-id>/v2.0`. Multi-tenant Entra issuers (`/common/`, `/organizations/`, `/consumers/`) require `OAUTH_IDP_ALLOWED_TENANTS`; Google requires `OAUTH_IDP_ALLOWED_DOMAINS` or `OAUTH_IDP_ALLOWED_USERS` |
| `OAUTH_IDP_CLIENT_ID` | *(none)* | Client ID registered at the provider. Required with `OAUTH_IDP_ISSUER` |
| `OAUTH_IDP_CLIENT_SECRET` | *(none)* | Client secret; when empty the server is a public client using PKCE |
| `OAUTH_IDP_SCOPES` | `openid email profile` | Scopes requested from the provider |
| `OAUTH_IDP_ALLOWED_TENANTS` | *(none)* | Comma-separated Entra tenant IDs (`tid` claim) |
| `OAUTH_IDP_ALLOWED_DOMAINS` | *(none)* | Comma-separated domains, matched against Google's `hd` or the e-mail domain. The e-mail must be vouched for (`email_verified: true`, matching `hd`, or an allow-listed tenant) |
| `OAUTH_IDP_ALLOWED_USERS` | *(none)* | Comma-separated `sub` values, values of `OAUTH_IDP_SUBJECT_CLAIM`, or vouched e-mail addresses. A fallback `preferred_username` never matches |
| `OAUTH_IDP_GROUP_CLAIM` | `groups` | Claim holding group or role names (`roles` for Entra app roles) |
| `OAUTH_IDP_GROUP_SCOPE_MAP` | *(none)* | JSON map of group to scopes, e.g. `{"soc-admins": "wazuh:read wazuh:write", "soc-analysts": "wazuh:read"}` |
| `OAUTH_IDP_DEFAULT_SCOPE` | `wazuh:read` | Scope for users in no mapped group; empty denies them |
| `OAUTH_IDP_SUBJECT_CLAIM` | `email` | Claim used as the audited identity. An unverified e-mail is never used; the server falls back to `preferred_username` (unless it looks like an e-mail address), then `sub` |
| `OAUTH_IDP_LOGIN_TTL` | `600` | Seconds a parked authorization request waits for the user to return from the provider (1–3600) |

The granted scope is the user's mapped scope intersected with the client's registered scope. With an IdP configured, the API-key sign-in form is disabled. Parked logins live in process memory, so run one instance or route `/oauth/authorize` and `/oauth/callback` to the same one.

The `OAUTH_IDP_*` settings are validated at startup whenever `OAUTH_IDP_ISSUER` is set, even if `AUTH_MODE` is not `oauth` (a warning is then logged and the provider is not used). Startup fails when the issuer is not `https://`, `OAUTH_IDP_CLIENT_ID` is empty, a multi-tenant Entra issuer has no `OAUTH_IDP_ALLOWED_TENANTS`, a Google issuer has neither `OAUTH_IDP_ALLOWED_DOMAINS` nor `OAUTH_IDP_ALLOWED_USERS`, `OAUTH_IDP_GROUP_SCOPE_MAP` is not a JSON object of strings or maps a group to no known scope, `OAUTH_IDP_DEFAULT_SCOPE` contains an unknown scope, or `OAUTH_ENABLE_DCR=true`. The provider's discovery document is fetched on the first sign-in, not at startup; if it cannot be fetched, the client is redirected back with `error=temporarily_unavailable`.

## Network, CORS and rate limiting

| Variable | Default | Description |
|----------|---------|-------------|
| `ALLOWED_ORIGINS` | `https://claude.ai,http://localhost:3000` | Comma-separated origins used for both CORS and the `Origin` check on `/mcp` and `/`. Matching is exact, so `https://*.example.com` does not work. A request whose `Origin` header is not listed gets `403 Origin not allowed`. Requests without an `Origin` header are accepted. `*` is honoured only in development |
| `TRUSTED_PROXIES` | *(none)* | Comma-separated proxy IPs whose `X-Forwarded-For`/`X-Real-IP` headers are trusted when working out the client IP for rate limiting. OAuth issuer derivation also trusts these addresses. Set it behind a reverse proxy |
| `RATE_LIMIT_REQUESTS` | `100` | Requests per window, per client IP (positive integer), for every route except `/mcp`, `/`, `/sse` and the probes, for example `/auth/token` and `/oauth/*` |
| `RATE_LIMIT_WINDOW` | `60` | Window for `RATE_LIMIT_REQUESTS`, in seconds (1–86400) |

`/mcp` and `/` apply `RATE_LIMIT_REQUESTS` per `RATE_LIMIT_WINDOW` to each authenticated principal and client IP; other routes apply it per client IP. Failed authentication attempts count against a per-IP bucket of the same size. Over-limit requests get `429 Rate limit exceeded` with a `Retry-After` header. `/health`, `/ready` and `/metrics` are never rate limited.

## Sessions

| Variable | Default | Description |
|----------|---------|-------------|
| `REDIS_URL` | *(none)* | Redis URL for sessions shared between instances, for example `redis://redis:6379/0`. Without it, sessions are kept in memory and are lost on restart |
| `SESSION_TTL_SECONDS` | `1800` | Redis key TTL for a session (positive integer). Read only when `REDIS_URL` is set |
| `MAX_SESSIONS` | `1000` | In-memory store: most sessions held at once (1–100000). At the limit, expired sessions are reclaimed, then the least recently active are evicted |
| `MAX_SESSIONS_PER_PRINCIPAL` | `100` | In-memory store: most sessions per principal (1–100000). The principal is the API key, or for OAuth the client plus the signed-in API key or IdP user; the principal's least recently active session is evicted first. Not applied to shared identities (`authless`, and OAuth tokens that carry neither a client nor a subject), which only `MAX_SESSIONS` bounds |

Only legacy (`initialize`-based) MCP clients create sessions; requests using the 2026-07-28 stateless protocol do not. Stored client metadata is truncated (client name, version and title; capability names only).

The session caps apply to the in-memory store; Redis expires keys itself and holds them outside the process. Eviction trades a memory outage for a re-initialize: a client holding several principals' credentials (or any caller in `AUTH_MODE=none`) can push other sessions out, and those clients then initialize again. Sessions also expire after 30 minutes without activity whatever the storage, so a `SESSION_TTL_SECONDS` above `1800` does not make them last longer.

With `REDIS_URL` set, the server starts even if Redis is unreachable. While Redis is down, session requests get `503 {"error": "Session store unavailable; retry shortly"}` with `Retry-After: 5`, and `/ready` returns `503`.

## Tool exposure and output

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_TOOLSETS` | `all` | Comma-separated toolsets to expose: `alerts`, `agents`, `vulnerabilities`, `analysis`, `web_search`, `compliance`, `system`, `response`, or `all`. Unknown names fail startup |
| `WAZUH_DISABLED_TOOLS` | *(none)* | Comma-separated tool names to hide, applied after `WAZUH_TOOLSETS`. Unknown names fail startup |
| `MAX_TOOL_RESPONSE_CHARS` | `1000000` | Maximum characters in one tool result (positive integer). Longer results are cut, with a note asking the caller to narrow the query |
| `RESPONSE_FORMAT` | `json` | `gcf` encodes tool results in Graph Compact Format, which uses fewer tokens and loses no data. It needs the `gcf-python` package, which `requirements.txt` and the Docker image include. Without it, and on any encoding error, results fall back to JSON. Any other value means JSON |

How tool exposure works:

- **Hidden tools** are removed from `tools/list`. A `tools/call` for one returns an `isError` result: `Tool '<name>' is disabled on this server`. Scope filtering still applies to the tools that remain.
- **Catalogue size:** the full catalogue of 55 tools is about 29 KB of JSON and is sent to the model with every request. Trimming it helps small local models most; see [Local LLMs](LOCAL_LLM.md).
- **External traffic:** `web_search` (`search_external_context`) is the only toolset that sends data outside your network. Drop it for air-gapped deployments.
- **Annotations and schemas:** every tool carries MCP tool annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`) and a closed input schema (`additionalProperties: false`). Annotations are hints for clients; the server still enforces authorization by scope.

## Active-response safety

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_PROTECTED_IPS` | *(none)* | Comma-separated IPs or CIDRs that `wazuh_block_ip`, `wazuh_firewall_drop` and `wazuh_host_deny` refuse to block. Loopback is always protected, and so is `WAZUH_HOST` when it is an IP address. Invalid entries are skipped, with a warning |
| `WAZUH_REQUIRE_ACTION_CONFIRMATION` | `true` when `ENVIRONMENT=production`, otherwise `false` | *Strict.* Every `wazuh:write` tool must be called with `confirm=true`. Write tools always advertise the optional `confirm` flag. An explicit value wins over the environment default; an empty value counts as unset |
| `WAZUH_ALLOW_MANAGER_AR` | `false` | *Strict.* Allows host-level actions against agent `000` (the Manager itself): isolate, kill, disable user, quarantine, generic active response, the IP-block tools with that agent, and `wazuh_restart` with `target=manager` |
| `WAZUH_ALLOW_FLEET_AR` | `false` | *Strict.* Allows `wazuh_block_ip` with `all_agents=true` (a block on every agent at once) |
| `WAZUH_QUARANTINE_DENY_PREFIXES` | *(none)* | Comma-separated directories `wazuh_quarantine_file` refuses, in addition to the built-in list, which cannot be removed: `/etc`, `/boot`, `/bin`, `/sbin`, `/lib`, `/lib32`, `/lib64`, `/usr`, `/proc`, `/sys`, `/dev`, `/var/ossec`, `/var/lib`, their `/private/...` forms on macOS, `/Library`, `/System`, `/Applications`, `C:\Windows`, `C:\Program Files` and `C:\Program Files (x86)`. Matching is case-insensitive and treats `/` and `\` alike |
| `WAZUH_QUARANTINE_ALLOW_PREFIXES` | *(none)* | When set, `wazuh_quarantine_file` only accepts paths under these directories (the deny list still applies). Paths must always be absolute |
| `WAZUH_AR_FIREWALL_UNDO_COMMAND` | *(none)* | Name of an active-response command you have deployed that removes a `firewall-drop` block. `wazuh_firewall_allow` refuses to run without it, because stock Wazuh cannot remove a block through the API. The name must match `[A-Za-z0-9_-]{1,64}`; a leading `!` is added if missing. An invalid name fails startup |
| `WAZUH_AR_HOSTDENY_UNDO_COMMAND` | *(none)* | Same, for removing a `host-deny` block with `wazuh_host_allow` |

The block tools also refuse `127.0.0.0/8`, `::1` and an IP-address `WAZUH_HOST` without any setting. `wazuh_active_response` refuses the `firewall-drop` and `host-deny` commands and points to `wazuh_firewall_drop` / `wazuh_host_deny`, so every IP block goes through the protected-target check. The active-response switches are read on each call, but an invalid spelling fails startup.

Active-response results report `execution_status: "dispatched"`: Wazuh confirms the command was delivered to the agent, not that the script ran. Check the effect with the matching `wazuh_check_*` tool. Blocks stay in place until removed. A positive `duration` is refused, because Wazuh ignores the timeout for API-triggered active response.

## Optional integrations

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_CLUSTERS_FILE` | `./config/clusters.json` | Multi-cluster file, relative to the working directory (`/app` in the container). If the file does not exist, the server runs single-cluster from the variables above. If it exists but is invalid, startup fails. See the [Multi-Cluster Guide](MULTI_CLUSTER.md). `compose.yml` mounts `./config` read-only at `/app/config` |
| `YDC_API_KEY` | *(none)* | You.com API key for `search_external_context`. Without it, the tool stays listed and returns `enabled: false` and a message |
| `YDC_BASE_URL` | `https://ydc-index.io` | You.com Search API base URL |
| `YDC_VERIFY_SSL` | `true` | *Strict.* Verify the You.com TLS certificate |

## Docker Compose variables

These are read by Docker Compose when it expands `compose.yml`, from the shell or from `.env`, not by the server.

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_BIND` | `127.0.0.1` | Host interface the port is published on. The loopback default assumes a reverse proxy on the same host. Set `0.0.0.0` only on a trusted network |
| `MCP_PORT` | `3000` | Host port. The container always listens on 3000 |
| `AUTH_MODE` | `bearer` | Passed through to the container |
| `VERSION` | `4.3.0` | Image tag (`wazuh-main-server:<VERSION>`) and build argument |
| `PYTHON_VERSION` | `3.13` | Base image Python version |

The local LLM stack (`compose.local-llm.yml`) has its own variables (`VLLM_*`, `WEBUI_SECRET_KEY`, `HF_TOKEN`, and others); see [Local LLMs](LOCAL_LLM.md).

Variables not listed on this page are not read by the server. In particular, `VERIFY_SSL` and `MCP_TRANSPORT` from older releases have no effect; use `WAZUH_VERIFY_SSL`.

## RBAC

| Scope | Tools | Covers |
|-------|-------|--------|
| `wazuh:read` | 41 | Alerts, agents, vulnerabilities, analysis, compliance, system monitoring, and the `wazuh_check_*` verification tools |
| `wazuh:write` | 14 | Active response (block, isolate, kill, disable user, quarantine, restart, generic command) and the matching rollback tools |

- **Fail-closed:** a token without a scope claim is read-only.
- **Enforcement:** `tools/list` returns only the tools the token may call, and `tools/call` checks the scope before running anything. A refusal comes back as an `isError` tool result.
- **Audit:** every `wazuh:write` call is logged twice on the `wazuh_mcp_server.audit` logger, as `AUDIT:` before execution and `AUDIT_OUTCOME:` after, with the principal, session and arguments.

## Authentication modes

| Mode | `AUTH_MODE` | How clients authenticate |
|------|-------------|--------------------------|
| Bearer | `bearer` | Exchange an API key for a JWT at `POST /auth/token`, then send `Authorization: Bearer <jwt>` |
| OAuth 2.0 | `oauth` | Authorization code with PKCE. Users sign in on `/oauth/authorize` with an API key, or at an OpenID Connect provider when `OAUTH_IDP_ISSUER` is set |
| Authless | `none` | No authentication. Read-only unless `AUTHLESS_ALLOW_WRITE=true`. Use only on a trusted network |

```bash
curl -s -X POST http://localhost:3000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "wazuh_..."}'
# {"access_token":"eyJ...","token_type":"bearer","expires_in":86400}
```

The JWT carries the API key's own scopes.

OAuth endpoints: `/.well-known/oauth-authorization-server` (RFC 8414), `/.well-known/oauth-protected-resource` (RFC 9728), `GET`/`POST /oauth/authorize`, `GET /oauth/callback` (identity-provider return; `404` without `OAUTH_IDP_ISSUER`), `POST /oauth/token`, `POST /oauth/revoke` and `POST /oauth/register`. The register endpoint returns `400` unless `OAUTH_ENABLE_DCR=true`. The two `/.well-known` endpoints return `404` when OAuth is not enabled.

## Production requirements

With `ENVIRONMENT=production`, which is the Docker image and `compose.yml` default:

- `AUTH_SECRET_KEY` is mandatory unless `AUTH_MODE=none`, must be at least 32 characters, and must not be a placeholder.
- A generated API key is read-only and never shown, so set `MCP_API_KEY` or `API_KEYS`.
- `ALLOWED_ORIGINS=*` is not honoured.
- A warning is logged if `AUTH_MODE=oauth` and `OAUTH_ISSUER_URL` is unset.
- `WAZUH_REQUIRE_ACTION_CONFIRMATION` defaults to `true`, so write tools need `confirm=true`.
- Disabled Manager certificate verification is logged as an error rather than a warning.

Example:

```env
ENVIRONMENT=production
WAZUH_HOST=wazuh.example.com
WAZUH_USER=mcp-service-account
WAZUH_PASS=<secret>
WAZUH_CA_BUNDLE=/app/certs/ca.pem    # CA that signed the Manager (and Indexer) certificates

WAZUH_INDEXER_HOST=wazuh-indexer.example.com
WAZUH_INDEXER_USER=<user>
WAZUH_INDEXER_PASS=<secret>
WAZUH_INDEXER_VERIFY_SSL=true

AUTH_MODE=bearer
AUTH_SECRET_KEY=<openssl rand -hex 32, identical on every instance>
MCP_API_KEY=wazuh_<43 characters>
MCP_API_KEY_SCOPES=wazuh:read        # add wazuh:write only for keys that may run active response
TRUSTED_PROXIES=10.0.0.1             # your reverse proxy
ALLOWED_ORIGINS=https://claude.ai

REDIS_URL=redis://redis:6379/0       # only needed for more than one instance
LOG_FORMAT=json
```

The server serves plain HTTP only. Terminate TLS at a reverse proxy or load balancer in front of it.

## Checking a configuration

```bash
# Liveness: 200 while the process is up
curl -s http://localhost:3000/health

# Readiness: Manager, Indexer, and memory; 200 when healthy, 503 otherwise (cached 5 s)
curl -s http://localhost:3000/ready | jq '.status, .services'

# Manager credentials (the same call the server makes)
curl -k -u "$WAZUH_USER:$WAZUH_PASS" -X POST "https://$WAZUH_HOST:${WAZUH_PORT:-55000}/security/user/authenticate"

# Indexer credentials
curl -k -u "$WAZUH_INDEXER_USER:$WAZUH_INDEXER_PASS" "https://$WAZUH_INDEXER_HOST:${WAZUH_INDEXER_PORT:-9200}/_cluster/health"
```

Apply `.env` changes by recreating the container:

```bash
docker compose up -d
```

For client setup (Claude, Open WebUI and others) see [Claude Integration](CLAUDE_INTEGRATION.md) and [Local LLMs](LOCAL_LLM.md).

---

**See also:** [Operations](OPERATIONS.md) · [Troubleshooting](TROUBLESHOOTING.md) · [Security](security/README.md) · [API Reference](api/README.md)
