# Upgrading

## Upgrading to the next release (after 4.3.0)

These changes are on `main` and listed under "Unreleased" in [CHANGELOG.md](CHANGELOG.md). Most are fixes; the ones below need action or change what clients see.

### 1. OAuth users sign in with an API key

`/oauth/authorize` now shows a sign-in page instead of approving every request. Each user pastes a `wazuh_` API key once; their token gets that key's scopes. Configure keys before upgrading an OAuth deployment, or nobody can sign in:

```env
MCP_API_KEY=wazuh_...                 # or API_KEYS=[...] for one key per user
MCP_API_KEY_SCOPES=wazuh:read         # add wazuh:write for users who may run active response
```

### 2. Re-mint bearer tokens once

Bearer JWTs are now bound to the API key they came from, and `MCP_API_KEY` got a stable id. Tokens minted before the upgrade reference the old id and are refused: exchange the key at `POST /auth/token` again. From then on tokens survive restarts and work across replicas.

### 3. Point legacy clients at `/mcp`

`/sse` returns `410 Gone`. It never completed a session (no `endpoint` event, no message route), so any client configured with it wasn't working anyway.

### 4. Startup is stricter

Values that used to be misread now stop the server with a message: `ENVIRONMENT` other than `development`/`dev`/`production`/`prod`, an unknown `AUTH_MODE`, non-positive `RATE_LIMIT_REQUESTS`/`RATE_LIMIT_WINDOW`/`SESSION_TTL_SECONDS`, `MAX_MEMORY_MB` below 64, and invalid `clusters.json` fields (booleans must be true/false, ports 1-65535). With `REDIS_URL` set, a bad TTL no longer falls back to the in-memory store.

### 5. Tool calls

- `duration` on `wazuh_block_ip` / `wazuh_firewall_drop` is refused when positive: Wazuh can't expire an API-triggered block. Blocks are permanent until removed.
- Arguments a tool doesn't declare are refused instead of ignored.
- Scope, confirmation and disabled-tool refusals are `isError` tool results (not JSON-RPC errors), so the model sees them.
- Active-response results include `execution_status: "dispatched"`; confirm effects with the `wazuh_check_*` tools.
- Manager log tools accept `limit` up to 500 (Wazuh's own maximum).
- Vulnerability results drop the always-null `status` and add `cvss_score` and `under_evaluation`.

### 6. Legacy sessions

A request without `Mcp-Session-Id` that isn't `initialize` is served without creating a session and gets no session header. Clients that skipped `initialize` and reused that header must initialize first (as the MCP spec requires).

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
in the manager so blocks expire; that does not work for API-dispatched commands, see
"Tool calls" above.)

### MCP protocol

No action required. The server now speaks the 2026-07-28 revision on the stateless
per-request path and continues to answer the `initialize` handshake for clients on
2024-11-05 through 2025-11-25.
