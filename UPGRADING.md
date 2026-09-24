# Upgrading

## Upgrading to the next release (after 4.3.0)

These changes are on `main` and listed under "Unreleased" in [CHANGELOG.md](CHANGELOG.md). Most are fixes; the sections below cover the ones that need action or change what clients see. Sections 1 to 3 can stop an existing deployment from working until you act.

### 1. The Manager certificate is verified by default

`WAZUH_ALLOW_SELF_SIGNED` now defaults to `false`. Earlier versions connected to the Manager without verifying its certificate, even with `WAZUH_VERIFY_SSL=true`. The stock Wazuh Manager API certificate is self-signed for `CN=wazuh.com` with no subjectAltName and cannot be verified, so a stock deployment stops connecting with `TLS certificate verification failed` until you choose one of:

- **Verify (recommended):** reissue the Manager API certificate with a subjectAltName matching `WAZUH_HOST`, mount its CA and set `WAZUH_CA_BUNDLE` (in `compose.yml`, uncomment the `./certs` volume and set `WAZUH_CA_BUNDLE=/app/certs/ca.pem`). The bundle replaces the system trust store for both the Manager and the Indexer, so include the Indexer's CA if it differs.
- **Keep the previous behaviour:** set `WAZUH_ALLOW_SELF_SIGNED=true`. The API password is then sent over an unverified connection; the server logs this at startup (as an error when `ENVIRONMENT=production`).

Clusters in `clusters.json` use `verify_ssl` and `ca_bundle` per cluster; `ca_bundle` falls back to `WAZUH_CA_BUNDLE`. See [Manager TLS](docs/configuration.md#manager-tls).

### 2. OAuth users must sign in

`/oauth/authorize` used to approve every request. It now requires the user to sign in, in one of two ways:

- **API key (default):** the user pastes a `wazuh_` API key on the server's sign-in page; the grant is capped at that key's scopes, and its tokens end when the key is revoked. Configure keys before upgrading an OAuth deployment, or nobody can sign in:

  ```env
  MCP_API_KEY=wazuh_...                 # or API_KEYS=[...] for one key per user
  MCP_API_KEY_SCOPES=wazuh:read         # add wazuh:write for users who may run active response
  ```

- **OpenID Connect:** set `OAUTH_IDP_ISSUER` and `OAUTH_IDP_CLIENT_ID` (plus `OAUTH_IDP_CLIENT_SECRET` for a confidential client) and register `<OAUTH_ISSUER_URL>/oauth/callback` as the redirect URI at the provider. Users sign in at Entra ID, Google Workspace, Okta or another OIDC provider, and `OAUTH_IDP_GROUP_SCOPE_MAP` / `OAUTH_IDP_DEFAULT_SCOPE` decide their scopes. See [Sign-in through an OpenID Connect identity provider](docs/configuration.md#sign-in-through-an-openid-connect-identity-provider).

### 3. Re-mint bearer tokens once

Bearer JWTs are now bound to the API key they came from, and `MCP_API_KEY` got a stable id derived from the key. Tokens minted before the upgrade reference the old id and are refused: exchange the key at `POST /auth/token` again. From then on tokens survive restarts and work across replicas, and revoking or rotating a key ends its tokens.

### 4. Active-response guard-rails

- **Write access is always explicit.** In development, the key generated when none is configured is now read-only, like in production. Set `MCP_API_KEY` and `MCP_API_KEY_SCOPES="wazuh:read wazuh:write"` for write tools.
- **Confirmation in production.** With `ENVIRONMENT=production` (set by the Dockerfile and `compose.yml`), every write tool requires `confirm=true` unless `WAZUH_REQUIRE_ACTION_CONFIRMATION=false`. LLM clients see the refusal and re-invoke after asking a person; scripted clients must pass `confirm: true`.
- **Fleet-wide blocks** (`all_agents=true` on `wazuh_block_ip`) need `WAZUH_ALLOW_FLEET_AR=true`.
- **The Manager as a target.** Active response against agent `000` and `wazuh_restart` with `target=manager` need `WAZUH_ALLOW_MANAGER_AR=true`.
- **Quarantine paths.** `wazuh_quarantine_file` refuses system and agent directories. `WAZUH_QUARANTINE_DENY_PREFIXES` adds to that list; `WAZUH_QUARANTINE_ALLOW_PREFIXES` restricts quarantine to the listed directories.
- **Targeted actions go through the dedicated tools.** `wazuh_active_response` refuses `!firewall-drop`, `!host-deny`, `!quarantine`, `!kill-process` and `!disable-account`; use `wazuh_firewall_drop`, `wazuh_host_deny`, `wazuh_quarantine_file`, `wazuh_kill_process` or `wazuh_disable_user`, which validate the target. Those tools, like `wazuh_block_ip`, now refuse loopback, the Manager's address and `WAZUH_PROTECTED_IPS`.

Invalid values for `WAZUH_REQUIRE_ACTION_CONFIRMATION`, `WAZUH_ALLOW_FLEET_AR` and `WAZUH_ALLOW_MANAGER_AR` stop the server at startup.

### 5. Tool calls

- `duration` on `wazuh_block_ip` / `wazuh_firewall_drop` is refused when positive: Wazuh can't expire an API-triggered block. Blocks are permanent until removed.
- Active-response results include `execution_status: "dispatched"`: Wazuh confirmed delivery, not execution. Confirm effects with the `wazuh_check_*` tools.
- Arguments a tool doesn't declare are refused instead of ignored.
- Scope, confirmation and disabled-tool refusals are `isError` tool results (not JSON-RPC errors), so the model sees them.
- `limit` on `get_wazuh_alerts` and `search_security_events` is capped at `MAX_ALERTS_PER_QUERY` (default 1000, unchanged), which was previously not applied.
- Manager log tools accept `limit` up to 500 (Wazuh's own maximum).
- Vulnerability results drop the always-null `status` and add `cvss_score` and `under_evaluation`.

### 6. Startup is stricter

Settings that used to be misread or only failed on the first tool call now stop the server with a message:

- missing `WAZUH_HOST`, `WAZUH_USER` or `WAZUH_PASS`;
- `ENVIRONMENT` other than `development`/`dev`/`production`/`prod`, or an unknown `AUTH_MODE`;
- non-positive `RATE_LIMIT_REQUESTS`/`RATE_LIMIT_WINDOW`/`SESSION_TTL_SECONDS`, or `MAX_MEMORY_MB` below 64;
- a `WAZUH_CA_BUNDLE` or per-cluster `ca_bundle` that does not exist or cannot be loaded;
- an incomplete OpenID Connect configuration (for example `OAUTH_IDP_ISSUER` without `OAUTH_IDP_CLIENT_ID`), or `OAUTH_ENABLE_DCR=true` together with `OAUTH_IDP_ISSUER`;
- a malformed `MCP_API_KEY` or unparseable `API_KEYS` (previously a warning, and the server ran with a generated key no client knew);
- a host setting that includes a port or path (`WAZUH_HOST=https://wazuh:55000/`; use `WAZUH_PORT`), or a CA bundle that is not PEM;
- invalid `clusters.json` fields (booleans must be true/false, ports 1-65535).

With `REDIS_URL` set, a bad TTL no longer falls back to the in-memory store.

When running from source without `MCP_HOST`, the server now binds `127.0.0.1` instead of `0.0.0.0`. The Docker image and Compose still listen on `0.0.0.0` inside the container.

### 7. Sessions and rate limits

- A request without `Mcp-Session-Id` that isn't `initialize` is served without creating a session and gets no session header. Clients that skipped `initialize` and reused that header must initialize first, as the MCP specification requires.
- The in-memory session store is capped at `MAX_SESSIONS` (default 1000) and `MAX_SESSIONS_PER_PRINCIPAL` (default 100). When a cap is reached, the least recently active sessions are evicted; a client whose session was evicted gets `404` and must initialize again. The caps do not apply to the Redis store, which expires sessions itself. Stored client metadata is truncated in both stores.
- `/` is an alias of `/mcp`. A `GET /` without `Accept: text/event-stream` now gets `405` like `/mcp`, instead of a JSON server description and a new session.
- With Redis, sessions last `SESSION_TTL_SECONDS` (previously capped at 30 minutes by the server).
- `RATE_LIMIT_REQUESTS` and `RATE_LIMIT_WINDOW` now apply to `/mcp` and `/`, which previously used the built-in 100 requests per 60 s regardless of the settings.

### 8. Point legacy clients at `/mcp`

`/sse` returns `410 Gone`. It never completed a session (no `endpoint` event, no message route), so a client configured with it was not working anyway.

## Upgrading to 4.3.0

4.3.0 is backward compatible at the protocol and API level, but three behaviors
that were already the intended design are now **enforced**. Review these before
upgrading a production deployment.

### 1. Write access is opt-in (RBAC fails closed)

A token with **no scope claim is read-only**. The 14 state-changing tools (active
response + rollback) now require the `wazuh:write` scope, which must be granted
explicitly. If you relied on unscoped tokens implicitly having write access, grant
it:

```env
MCP_API_KEY_SCOPES=wazuh:read wazuh:write
```

In authless mode (`AUTH_MODE=none`), write tools are disabled unless
`AUTHLESS_ALLOW_WRITE=true`.

### 2. `AUTH_SECRET_KEY` is required in production

With `ENVIRONMENT=production` and `AUTH_MODE` other than `none`, the server refuses
to start without `AUTH_SECRET_KEY`. Set a stable secret (the same value across
replicas), otherwise tokens are invalidated on every restart:

```env
AUTH_SECRET_KEY=<32+ char secret>
```

### 3. Alerts come from the Indexer, not the Manager

The Wazuh Manager REST API has no alerts endpoint, and from Wazuh 4.8 vulnerability data is
only in the Indexer. Alert, aggregation, vulnerability, and alert-backed compliance tools
require the Wazuh Indexer (see [WAZUH_COMPATIBILITY.md](WAZUH_COMPATIBILITY.md)):

```env
WAZUH_INDEXER_HOST=<indexer-host>
WAZUH_INDEXER_USER=<user>
WAZUH_INDEXER_PASS=<pass>
```

Without it, those tools return a clear "Indexer not configured" error rather than
silently empty results.

### Active-response rollback tools

`wazuh_firewall_allow` and `wazuh_host_allow` no longer silently re-block an
address. Stock Wazuh cannot remove a firewall-drop / hosts.deny block through the
API, so these tools now require an operator-deployed undo script named via
`WAZUH_AR_FIREWALL_UNDO_COMMAND` / `WAZUH_AR_HOSTDENY_UNDO_COMMAND`, or they refuse
with an actionable error. (The 4.3.0 notes also suggested an `<active-response><timeout>`
in the manager so blocks expire; that does not work for API-dispatched commands; see
"Tool calls" in the next-release section above.)

### MCP protocol

No action required. The server now speaks the 2026-07-28 revision on the stateless
per-request path and continues to answer the `initialize` handshake for clients on
2024-11-05 through 2025-11-25.
