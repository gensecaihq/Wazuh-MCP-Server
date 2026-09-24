# Claude Integration Guide

How to connect the Wazuh MCP Server to Claude (claude.ai, Claude Desktop) as a custom connector, and how to call the server directly from scripts.

## Requirements

- A Claude plan with custom connectors. Anthropic currently lists Free (one custom connector), Pro, Max, Team and Enterprise; check [Anthropic's help article](https://support.claude.com/en/articles/11175166-get-started-with-custom-connectors-using-remote-mcp) for the current terms.
- The server reachable over **HTTPS from the public internet**. Claude connects to remote MCP servers from Anthropic's cloud, not from your machine, so a server that is only reachable on your LAN or VPN will not work unless you allowlist Anthropic's IP ranges.
- `AUTH_MODE=oauth`. Claude's connector dialog accepts an OAuth client ID and secret under **Advanced settings**; it has no field for a static bearer token.

`compose.yml` publishes the server on `127.0.0.1:3000` over plain HTTP and runs with `ENVIRONMENT=production`. Put a TLS-terminating reverse proxy in front of it and route the public hostname to port 3000.

## Server setup (OAuth)

Add to `.env`:

```bash
AUTH_MODE=oauth
AUTH_SECRET_KEY=<output of: openssl rand -hex 32>      # required in production
OAUTH_ISSUER_URL=https://mcp.example.com                # the public HTTPS URL, no trailing slash
MCP_API_KEY=wazuh_<43 url-safe characters>               # see "API keys" below
# MCP_API_KEY_SCOPES="wazuh:read wazuh:write"            # omit for read-only
```

Generate a key in the required format (`wazuh_` followed by 43 URL-safe base64 characters):

```bash
echo "wazuh_$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')"
```

Start the server and check it:

```bash
docker compose up -d
curl -s https://mcp.example.com/health
```

Set `OAUTH_ISSUER_URL` explicitly. Without it the issuer is derived from the request, and `X-Forwarded-Proto` / `X-Forwarded-Host` are honoured only when the proxy's address is in `TRUSTED_PROXIES` (loopback is always trusted); a wrong issuer breaks discovery.

### API keys

Unless an identity provider is configured (see [Sign-in through your identity provider](#sign-in-through-your-identity-provider)), each user signs in with a `wazuh_` API key. The key determines both the identity recorded on the token and the maximum scope that can be granted.

- **One key:** `MCP_API_KEY`. Its scopes come from `MCP_API_KEY_SCOPES` (space-separated); unset means `wazuh:read` only.
- **One key per user:** `API_KEYS`, a JSON array. The server stores only an HMAC-SHA256 of each key, computed with `AUTH_SECRET_KEY`:

  ```bash
  python3 -c 'import hmac,hashlib,secrets,os
  k = "wazuh_" + secrets.token_urlsafe(32)
  print("key: ", k)
  print("hash:", hmac.new(os.environ["AUTH_SECRET_KEY"].encode(), k.encode(), hashlib.sha256).hexdigest())'
  ```

  ```bash
  API_KEYS=[{"id":"alice","name":"Alice","key_hash":"<hash>","created_at":"2026-09-01T00:00:00Z","scopes":["wazuh:read"]}]
  ```

  `id`, `name`, `key_hash`, `created_at` are required; `scopes`, `expires_at` and `active` are optional. Changing `AUTH_SECRET_KEY` invalidates every hash.

If no key is configured, the server generates a temporary key at startup. In production that key is read-only and never displayed, so nobody can sign in with it; only with `ENVIRONMENT=development` is it printed (with read and write scope). Configure a key explicitly.

## Add the connector in Claude

**Pro / Max (and Free):**

1. **Customize → Connectors**, click **+**, then **Add custom connector**.
2. URL: `https://mcp.example.com/mcp`.
3. **Advanced settings → OAuth Client ID:** `claude-desktop`. Leave the client secret empty.
4. Save, then **Connect**. A browser window opens on the server's sign-in page.
5. Paste your `wazuh_` API key and click **Authorize**. With an identity provider configured, the browser goes to the provider's sign-in page instead.

**Team / Enterprise:** an owner adds the connector under **Organization settings → Connectors → Add → Custom → Web** with the same URL and client ID. Members then open **Customize → Connectors**, find the connector and click **Connect**; each member signs in with their own key.

Custom connectors work in Claude Desktop as well as on claude.ai.

### What happens during sign-in

1. Claude reads `/.well-known/oauth-protected-resource` (RFC 9728) and `/.well-known/oauth-authorization-server` (RFC 8414). When `OAUTH_ISSUER_URL` is set, a `401` from `/mcp` also points to the protected resource metadata in its `WWW-Authenticate` header.
2. Claude opens `/oauth/authorize` with a PKCE S256 challenge. PKCE is mandatory; requests without it are rejected.
3. The sign-in page asks for a `wazuh_` API key. The granted scope is the intersection of what Claude requested, what the client is registered for, and the key's scopes, so a read-only key cannot obtain `wazuh:write`. (With an identity provider, this step happens at the provider; see below.)
4. Claude exchanges the code at `/oauth/token` for an access token and a refresh token.

Token response from a local test: no scope requested (the server then assumes `wazuh:read wazuh:write`) and a read-only `MCP_API_KEY`:

```json
{"access_token": "...", "token_type": "Bearer", "expires_in": 3600, "refresh_token": "...", "scope": "wazuh:read"}
```

Tokens carry the key's identity, so RBAC checks, rate limiting and the audit log (`client=oauth:claude-desktop:<key id>`) are per user. They stay bound to the key: removing or deactivating it in `API_KEYS` ends the user's access on the next request, before the token expires.

### The pre-registered client

The server registers one public client at startup:

| Field | Value |
|-------|-------|
| `client_id` | `claude-desktop` |
| Client secret | none (`token_endpoint_auth_method: none`, PKCE required) |
| Redirect URIs | `https://claude.ai/api/mcp/auth_callback`, `https://claude.com/api/mcp/auth_callback` |
| Grant types | `authorization_code`, `refresh_token` |

### Dynamic client registration

`/oauth/register` is disabled by default and returns:

```json
{"error": "invalid_request", "error_description": "Dynamic client registration is disabled"}
```

With `OAUTH_ENABLE_DCR=true` the endpoint is advertised in the metadata and accepts unauthenticated registrations, limited to:

- `grant_types` ⊆ `authorization_code`, `refresh_token`
- `token_endpoint_auth_method` ∈ `none`, `client_secret_post`, `client_secret_basic`
- redirect URIs using `https` (plain `http` only for loopback) and without fragments

Registered clients still need a user API key to obtain a grant. Enable DCR only for clients that cannot use `claude-desktop`.

### Sign-in through your identity provider

Instead of API keys, users can sign in with their organisation account (Entra ID, Google Workspace, Okta, Keycloak). Register an application at the provider with the redirect URI `<OAUTH_ISSUER_URL>/oauth/callback`, then set at least:

```env
AUTH_MODE=oauth
OAUTH_ISSUER_URL=https://mcp.example.com
OAUTH_IDP_ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0
OAUTH_IDP_CLIENT_ID=<application id>
OAUTH_IDP_GROUP_SCOPE_MAP={"soc-admins": "wazuh:read wazuh:write", "soc-analysts": "wazuh:read"}
```

The connector setup in Claude is unchanged (client ID `claude-desktop`). When a user connects, the browser goes to the provider; the API-key sign-in page is disabled. After sign-in the server verifies the ID token (RS256 signature against the provider's JWKS, issuer, audience, expiry and nonce), applies the allow-lists (`OAUTH_IDP_ALLOWED_TENANTS`, `OAUTH_IDP_ALLOWED_DOMAINS`, `OAUTH_IDP_ALLOWED_USERS`) and grants the scope mapped from the user's groups by `OAUTH_IDP_GROUP_SCOPE_MAP`, or `OAUTH_IDP_DEFAULT_SCOPE` (default `wazuh:read`) when no group matches. Tokens carry the user's identity, so the audit log records `oauth:claude-desktop:<user>`.

The server refuses to start with a Google issuer and no `OAUTH_IDP_ALLOWED_DOMAINS` or `OAUTH_IDP_ALLOWED_USERS`, or with a multi-tenant Entra issuer (`/common/`, `/organizations/`) and no `OAUTH_IDP_ALLOWED_TENANTS`, because either would admit any account. Users disabled at the provider keep access until their tokens expire or are revoked. All settings: [Configuration](configuration.md#sign-in-through-an-openid-connect-identity-provider); security details: [Security guide](security/README.md#oauth-mode-auth_modeoauth).

### Token lifetimes and revocation

| Setting | Default |
|---------|---------|
| `OAUTH_ACCESS_TOKEN_TTL` | 3600 s |
| `OAUTH_REFRESH_TOKEN_TTL` | 86400 s |
| `OAUTH_AUTHORIZATION_CODE_TTL` | 600 s |

- Refresh tokens rotate on every use. Presenting an already-used refresh token revokes that grant only; other users of the shared `claude-desktop` client are unaffected.
- `POST /oauth/revoke` (RFC 7009) revokes a token.
- Access tokens are signed JWTs and remain valid across restarts and replicas that share `AUTH_SECRET_KEY`. Authorization codes, pending identity-provider logins, refresh tokens and the revocation list are held in process memory: after a restart, users sign in again once their access token expires, and with several replicas the OAuth endpoints need sticky routing.

### Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| `/.well-known/oauth-protected-resource` | Protected resource metadata (RFC 9728) |
| `/oauth/authorize` | Sign-in page (GET) and API-key form submission (POST); redirects to the identity provider when one is configured |
| `/oauth/callback` | Return from the identity provider (only with `OAUTH_IDP_ISSUER`) |
| `/oauth/token` | Code exchange and refresh |
| `/oauth/revoke` | Token revocation (RFC 7009) |
| `/oauth/register` | Dynamic client registration, only with `OAUTH_ENABLE_DCR=true` |

## Write tools and confirmation

Keys or identity-provider groups that grant `wazuh:write` expose the 14 active-response tools. With `ENVIRONMENT=production` (the `compose.yml` default) the confirmation gate is on: a write-tool call without `confirm: true` is refused with a message asking for human approval, and Claude has to call the tool again with `confirm: true`. Approve that second call only after checking the target. Fleet-wide blocks (`WAZUH_ALLOW_FLEET_AR`) and actions against the Manager (`WAZUH_ALLOW_MANAGER_AR`) stay refused unless the operator enables them. See [Active response](api/active-response.md#safety-controls).

## Other authentication modes

| `AUTH_MODE` | Use |
|-------------|-----|
| `oauth` | Claude connectors; interactive sign-in per user |
| `bearer` (default) | Scripts, gateways and MCP clients that can send a static `Authorization` header |
| `none` | Local development only. Read-only unless `AUTHLESS_ALLOW_WRITE=true` |

`AUTH_MODE=none` exposes the server to anyone who can reach it; never use it on a public URL.

## Common mistake: `claude_desktop_config.json`

`claude_desktop_config.json` configures local (stdio) MCP servers, which Claude Desktop launches as processes. It is a separate mechanism from custom connectors and does not accept a remote `url`:

```json
{
  "mcpServers": {
    "wazuh-security": {
      "url": "https://mcp.example.com/mcp",
      "headers": { "Authorization": "Bearer ..." }
    }
  }
}
```

Claude Desktop rejects this with a schema error on the missing `command` field. Add the server as a custom connector instead.

## Transport

- Endpoint: `/mcp` (Streamable HTTP; POST, GET for an SSE stream, DELETE to end a legacy session). `POST /` is served by the same handler.
- `/sse` returns `410 Gone`: `{"error":"The legacy /sse transport is not supported. Use the Streamable HTTP endpoint /mcp.","endpoint":"/mcp"}`.
- Protocol versions: `2026-07-28` (stateless, no handshake) and, through the `initialize` handshake, `2025-11-25`, `2025-06-18`, `2025-03-26`, `2024-11-05`. An unsupported `MCP-Protocol-Version` header is rejected with the list of supported versions.
- Capabilities: tools, prompts, resources (including templates) and completions. `logging/setLevel` is available to legacy-handshake clients. Resource subscriptions and `listChanged` notifications are not offered. Tool results are text.
- Browser-originated requests are checked against `ALLOWED_ORIGINS` (default `https://claude.ai,http://localhost:3000`). A request with any other `Origin` header gets `403`; requests without an `Origin` header are not affected.

## Programmatic access (bearer mode)

Exchange an API key for a JWT. The token is bound to that key (revoking or rotating the key ends it) and carries the key's scopes; lifetime is `TOKEN_LIFETIME_HOURS` (default 24, maximum 8760).

```bash
TOKEN=$(curl -s -X POST http://127.0.0.1:3000/auth/token \
  -H 'Content-Type: application/json' \
  -d "{\"api_key\": \"$MCP_API_KEY\"}" | jq -r .access_token)
```

```json
{"access_token": "eyJhbGciOiJI...", "token_type": "bearer", "expires_in": 86400}
```

### Stateless request (2026-07-28)

Every request carries `MCP-Protocol-Version`, `Mcp-Method` (and `Mcp-Name` for `tools/call`, `prompts/get`, `resources/read`), plus the version in `params._meta`. No session is created.

```bash
curl -s http://127.0.0.1:3000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -H 'MCP-Protocol-Version: 2026-07-28' \
  -H 'Mcp-Method: tools/call' \
  -H 'Mcp-Name: get_wazuh_alerts' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call",
       "params":{"name":"get_wazuh_alerts","arguments":{"limit":10},
                 "_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}'
```

`server/discover` returns the supported versions and capabilities:

```json
{"resultType": "complete", "supportedVersions": ["2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"], "capabilities": {"tools": {}, "prompts": {}, "resources": {}, "completions": {}}, "ttlMs": 3600000, "cacheScope": "private", "_meta": {"io.modelcontextprotocol/serverInfo": {"name": "Wazuh MCP Server", "version": "4.3.0"}}}
```

### Legacy handshake (2025-11-25 and earlier)

Send `initialize`; the response carries an `MCP-Session-Id` header to send on later requests. Sessions are created only by `initialize` (or a GET stream).

```python
import httpx

BASE = "http://127.0.0.1:3000"

with httpx.Client(base_url=BASE) as client:
    token = client.post("/auth/token", json={"api_key": "wazuh_..."}).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}", "Accept": "application/json, text/event-stream"}

    init = client.post("/mcp", headers=headers, json={
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "script", "version": "1.0"}},
    })
    headers["MCP-Session-Id"] = init.headers["MCP-Session-Id"]
    headers["MCP-Protocol-Version"] = "2025-11-25"

    tools = client.post("/mcp", headers=headers,
                        json={"jsonrpc": "2.0", "id": 2, "method": "tools/list"}).json()
    print(len(tools["result"]["tools"]))
```

Do not send an `Origin` header from scripts unless it is listed in `ALLOWED_ORIGINS`; a local test with `Origin: http://localhost` returned `403 {"detail":"Origin not allowed: http://localhost"}`.

Read-only tokens see 41 tools; tokens with `wazuh:write` see all 55 (plus `list_wazuh_clusters` in [multi-cluster](MULTI_CLUSTER.md) mode).

---

[Configuration](configuration.md) · [Troubleshooting](TROUBLESHOOTING.md) · [Back to README](../README.md)
