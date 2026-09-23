# Security Guide

How Wazuh MCP Server authenticates clients, limits what they can do, and protects the Wazuh
deployment behind it, plus the settings to review before running it in production. Applies to
the current `main` branch (package version 4.3.0 plus the unreleased changes in
[CHANGELOG.md](../../CHANGELOG.md)).

To report a vulnerability, see [SECURITY.md](../../SECURITY.md).

## Contents

- [Architecture and trust boundaries](#architecture-and-trust-boundaries)
- [Client authentication](#client-authentication)
- [Authorization (RBAC scopes)](#authorization-rbac-scopes)
- [Active response safeguards](#active-response-safeguards)
- [HTTP layer protections](#http-layer-protections)
- [Credential handling and redaction](#credential-handling-and-redaction)
- [Audit logging](#audit-logging)
- [Connections to Wazuh](#connections-to-wazuh)
- [Container and deployment hardening](#container-and-deployment-hardening)
- [CI security checks](#ci-security-checks)
- [Known limitations](#known-limitations)
- [Production checklist](#production-checklist)

## Architecture and trust boundaries

```
MCP client ──HTTPS──> reverse proxy (TLS) ──HTTP──> Wazuh MCP Server ──HTTPS──> Wazuh Manager API (:55000)
                                                                    └─HTTPS──> Wazuh Indexer (:9200)
```

- The server listens on **plain HTTP** (`MCP_HOST`/`MCP_PORT`, default `0.0.0.0:3000`). It has no
  inbound TLS listener; terminate TLS at a reverse proxy.
- It holds one Wazuh Manager API account and, optionally, one Indexer account per cluster.
  Every MCP client acts through those accounts, so the server's own authentication and scope
  checks are what separate MCP users from each other.
- Tool output (alert text, log lines, rule descriptions) can contain attacker-controlled
  content. The server's `instructions` string tells clients to treat tool output as untrusted
  data and to confirm active-response targets with a human. That is guidance to the model, not
  an enforcement mechanism; the enforced controls are described below.

## Client authentication

`AUTH_MODE` selects the mode (`bearer` by default; `oauth`; `none`). Any other value stops the
server at startup.

### API keys

- Format: `wazuh_` followed by 43 URL-safe characters (49 characters total). Generate one with
  `python -c "import secrets; print('wazuh_' + secrets.token_urlsafe(32))"`.
- Keys are stored only as HMAC-SHA256 digests keyed with `AUTH_SECRET_KEY` and compared with
  `hmac.compare_digest` (`auth.py`).
- `MCP_API_KEY` configures one key. Its id is derived from the key's HMAC, so it is identical
  across restarts and replicas that share `AUTH_SECRET_KEY`. `API_KEYS` (JSON array) configures
  several keys, one per user.
- `MCP_API_KEY_SCOPES` sets the env key's scopes. It defaults to `wazuh:read`; write access
  must be granted explicitly (`wazuh:read wazuh:write`).
- If no key is configured, the server generates one at startup: read+write outside production,
  read-only (with a warning) when `ENVIRONMENT=production`.

### Bearer mode (`AUTH_MODE=bearer`)

`POST /auth/token` with `{"api_key": "wazuh_..."}` returns an HS256 JWT signed with
`AUTH_SECRET_KEY`, valid for `TOKEN_LIFETIME_HOURS` (default 24). On every request
(`verify_bearer_token` in `auth.py`):

- the signature and `exp` are verified, and a token without `exp` is refused;
- refresh-type tokens are refused as access tokens;
- the token's `sub` must name an API key that still exists, is active and has not expired, so
  removing or rotating a key ends its tokens;
- a token without a `scope` claim is treated as read-only.

There is no refresh flow for these tokens; clients request a new one with the API key.

### OAuth mode (`AUTH_MODE=oauth`)

Implemented in `oauth.py`:

- **Sign-in at an identity provider** (optional, `OAUTH_IDP_ISSUER`). The user authenticates at the OIDC
  provider; the ID token's RS256 signature (from the provider's JWKS; `none`/HMAC are never accepted),
  `iss`, `aud`, `exp` and `nonce` are verified, tenant/domain/user allow-lists are applied, and the scope
  comes from the user's groups. An e-mail is only used as identity when vouched for
  (`email_verified`, Google `hd`, or an allow-listed Entra tenant). A Google issuer without an allow-list,
  and multi-tenant Entra issuers without `OAUTH_IDP_ALLOWED_TENANTS`, are refused at startup.
- **Sign-in with an API key** (without an IdP). `GET /oauth/authorize` renders a sign-in page. The user pastes a
  `wazuh_` API key; the granted scope is the intersection of the requested scope, the client's
  registered scope and the key's scopes. If the key has none of the requested scopes the
  request is refused. Tokens carry the key id, so rate limits and audit records are per user.
  Tokens stay bound to that key: removing or deactivating it ends the user's OAuth access tokens
  as well as bearer JWTs minted from it.
- **PKCE `S256` is mandatory**; `plain` and missing challenges are rejected.
- **Authorization codes** are single-use and expire after `OAUTH_AUTHORIZATION_CODE_TTL`
  (default 600 s). The redirect URI must exactly match a registered one; the authorization
  response includes the RFC 9207 `iss` parameter.
- **Tokens** are HS256 JWTs. Access tokens last `OAUTH_ACCESS_TOKEN_TTL` (default 3600 s),
  refresh tokens `OAUTH_REFRESH_TOKEN_TTL` (default 86400 s).
- **Refresh rotation with replay detection.** Each refresh issues a new refresh token and
  revokes the old one. Presenting an already-used refresh token revokes every token in that
  grant's family (one user's authorization), not every user of the client.
- **Revocation** (`POST /oauth/revoke`, RFC 7009) records both the token string and its `jti`,
  so a revoked token cannot be replayed under a different base64url spelling.
- **Confidential clients** must present their secret at the token endpoint. The pre-registered
  client (`client_id=claude-desktop`, redirect URIs on `claude.ai`/`claude.com`) is a public
  client secured by PKCE.
- **Dynamic Client Registration** is off (`OAUTH_ENABLE_DCR=false`). When enabled, redirect URIs
  must be `https` (or `http` on `localhost`/`127.0.0.1`/`::1`) without fragments,
  `grant_types` must be a subset of `authorization_code`/`refresh_token`,
  `token_endpoint_auth_method` must be `none`, `client_secret_post` or `client_secret_basic`, and
  registration stops at roughly 1000 clients.
- **Issuer.** Set `OAUTH_ISSUER_URL`. Without it the issuer is derived from the request and
  `X-Forwarded-Proto`/`X-Forwarded-Host` are honored only from loopback or `TRUSTED_PROXIES`.
- **Discovery.** `/.well-known/oauth-authorization-server` (RFC 8414) and
  `/.well-known/oauth-protected-resource` (RFC 9728). When `OAUTH_ISSUER_URL` is set, 401
  responses carry `WWW-Authenticate: Bearer resource_metadata="..."`.

### Authless mode (`AUTH_MODE=none`)

No authentication. Every caller gets `wazuh:read`; write tools stay unavailable unless
`AUTHLESS_ALLOW_WRITE=true`. Use only on a trusted, isolated network.

### Signing secret

`AUTH_SECRET_KEY` signs JWTs and keys the API-key HMAC. With `ENVIRONMENT=production` and
`AUTH_MODE` other than `none`, startup fails if it is missing, shorter than 32 characters, or
looks like a placeholder (`change_me`, `example`, `<...>`, `your-secret`). Outside production a
random per-process value is generated, which invalidates tokens on restart. Use the same value
on every replica.

## Authorization (RBAC scopes)

Two scopes exist: `wazuh:read` and `wazuh:write`. Enforcement is in `handle_tools_call`
(`server.py`):

- `WRITE_SCOPE_TOOLS` lists the 14 state-changing tools: `wazuh_block_ip`,
  `wazuh_isolate_host`, `wazuh_kill_process`, `wazuh_disable_user`, `wazuh_quarantine_file`,
  `wazuh_active_response`, `wazuh_firewall_drop`, `wazuh_host_deny`, `wazuh_restart`,
  `wazuh_unisolate_host`, `wazuh_enable_user`, `wazuh_restore_file`, `wazuh_firewall_allow`,
  `wazuh_host_allow`.
- `READ_SCOPE_TOOLS` lists every read tool explicitly. The scope lookup fails closed: any name
  not in that list requires `wazuh:write`. A name in neither set is rejected as an unknown tool
  before the scope check.
- Tokens without `wazuh:write` do not see write tools in `tools/list`, and calls to them are
  refused at `tools/call` time.
- Scope, confirmation, disabled-tool and unknown-argument refusals are returned as tool results
  with `isError: true`, so the model sees the reason.
- `WAZUH_TOOLSETS` and `WAZUH_DISABLED_TOOLS` remove tools from `tools/list` and refuse them at
  call time, whatever the token's scope. Unknown names fail at startup.
- Tool input schemas are closed (`additionalProperties: false`), and undeclared arguments are
  refused.
- Every tool carries MCP annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`,
  `openWorldHint`) derived from its scope, so clients and gateways can require approval for
  write tools.

## Active response safeguards

In addition to the `wazuh:write` scope:

| Control | Behavior | Setting |
|---|---|---|
| Confirmation gate | Write tools require `confirm=true`; otherwise the call is refused with instructions to get human approval. The `confirm` property is added to write-tool schemas. | `WAZUH_REQUIRE_ACTION_CONFIRMATION=true` (default `false`) |
| Manager agent guard | Host-level actions targeting agent `000` (the Manager) are refused. | `WAZUH_ALLOW_MANAGER_AR=true` to override |
| Protected targets | IP-blocking tools (`wazuh_block_ip`, `wazuh_firewall_drop`, `wazuh_host_deny`) refuse loopback, the Manager's IP (when `WAZUH_HOST` is an IP), and anything in the list. Leading-zero and IPv4-mapped IPv6 spellings are normalized first. | `WAZUH_PROTECTED_IPS` (comma-separated IPs/CIDRs) |
| Explicit targeting | A PUT to `/active-response` is sent without `agents_list` (which Wazuh treats as every agent) only when the caller explicitly asked for all agents; a target that yields no numeric agent id is refused. | none |
| No expiring blocks | A positive `duration` is refused because Wazuh ignores the timeout for API-dispatched commands; blocks are permanent until removed. | none |
| Rollback tools | `wazuh_firewall_allow` and `wazuh_host_allow` refuse unless an undo command is configured, instead of re-running the block. | `WAZUH_AR_FIREWALL_UNDO_COMMAND`, `WAZUH_AR_HOSTDENY_UNDO_COMMAND` |

Active-response results report `execution_status: "dispatched"`: Wazuh confirms delivery to the
agent, not execution. Use the `wazuh_check_*` tools to confirm the effect.

## HTTP layer protections

Implemented in `security.py` and `server.py`:

- **Origin validation.** On `/mcp` (POST, GET, DELETE) and `/`, a request with an `Origin`
  header not in `ALLOWED_ORIGINS` gets HTTP 403. Requests without `Origin` are accepted. A
  literal `*` is honored only when `ENVIRONMENT=development`.
- **CORS.** Origins come from `ALLOWED_ORIGINS` (default `https://claude.ai,http://localhost:3000`).
  If it is empty or `*` outside development, the allow list falls back to `https://claude.ai`
  and `https://claude.anthropic.com`. Methods: GET, POST, DELETE, OPTIONS. Allowed headers are
  an explicit list that includes `Authorization`, `MCP-Protocol-Version`, `MCP-Session-Id`,
  `Mcp-Method`, `Mcp-Name` and `Last-Event-ID`.
- **Rate limiting.**
  - `/mcp` and `/`: a sliding window of `RATE_LIMIT_REQUESTS` per `RATE_LIMIT_WINDOW` seconds
    (default 100 per 60 s) per principal and client IP.
  - Failed authentication on the MCP endpoints is counted per client IP in the same limiter;
    a client that keeps failing gets 429.
  - Other routes (for example `/auth/token` and `/oauth/*`) use a per-IP sliding window
    configured by `RATE_LIMIT_REQUESTS` (default 100) and `RATE_LIMIT_WINDOW` (default 60 s).
  - `/health`, `/ready`, `/metrics` and their aliases are exempt.
  - A 429 carries `Retry-After`: the seconds until the oldest request leaves the window.
- **Client IP.** `X-Forwarded-For` and `X-Real-IP` are used only when the direct peer is loopback
  or listed in `TRUSTED_PROXIES`; the rightmost untrusted address in `X-Forwarded-For` is taken.
- **Body size.** POST/PUT/PATCH bodies over 1 MB are rejected with 413, checked against
  `Content-Length` and again while streaming (covers chunked uploads). JSON nesting is capped at
  64 levels; JSON-RPC batches at 100 items.
- **Request screening.** Headers and query strings are checked for script-injection,
  path-traversal and shell patterns. The JSON-RPC body on `/mcp` is exempt because analysts
  legitimately search for such strings; tool arguments go through typed validators instead
  (agent/rule ids, IPs via `ipaddress`, hashes, timestamps, active-response command names).
- **Response headers.** `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `X-XSS-Protection: 1; mode=block`,
  `Strict-Transport-Security: max-age=31536000; includeSubDomains`, and
  `Content-Security-Policy: default-src 'self'` unless a route sets a stricter one (the OAuth
  sign-in page does). HSTS only takes effect when the client reaches the server over HTTPS.
- **Memory guard.** Requests other than health/metrics probes get 503 when process memory
  exceeds `MAX_MEMORY_MB` (default 512, minimum 64).

## Credential handling and redaction

- **Wazuh Manager.** The client exchanges `WAZUH_USER`/`WAZUH_PASS` (HTTP Basic) at
  `POST /security/user/authenticate` for a Wazuh JWT and re-authenticates when it expires.
  Other requests carry only the JWT.
- **Log redaction.** `SanitizingLogFilter` is attached to the emitting handlers (including
  uvicorn's). It redacts credentials in URLs (`user:pass@host`), `Bearer` and `Basic`
  credentials, values after `password`, `token`, `api_key`, `secret` and `authorization` labels,
  `wst_` tokens, `wazuh_` API keys and bare JWTs. It applies to the message, its arguments,
  exception tracebacks and structured `extra` fields.
- **Tool output redaction.** Every tool result passes through `_sanitize_output_text`, which
  redacts `password`/`passwd`/`pwd`, `api_key`/`secret`/`token` key-value pairs and
  `Authorization:` headers before the text reaches the client. Results are capped at
  `MAX_TOOL_RESPONSE_CHARS` (default 1,000,000) and truncated with a note.
- **Error text.** `resources/read` does not return raw backend exception text.
- **Clusters file.** `clusters.json` supports `${ENV_VAR}` interpolation so secrets need not be
  stored in the file.

Keep `.env` out of version control and readable only by the service account (`chmod 600 .env`).
If you use a secret manager, inject the values as environment variables at container start.

## Audit logging

Audit logging is always on. Each write-tool call produces two WARNING records on the
`wazuh_mcp_server.audit` logger:

```
AUDIT: tool=wazuh_block_ip client=<principal> session=<session_id> args={...}
AUDIT_OUTCOME: tool=wazuh_block_ip outcome=success principal=<principal> session=<session_id> duration_ms=<n> args={...}
```

The first is written before the action runs, the second after it with the outcome. The
`parameters` and `confirm` arguments are omitted. The principal is the API key id
(`jwt:<key id>` for bearer JWTs, `oauth:<client>:<key id>` for OAuth, `authless` in authless
mode). Records go to the server's standard log output; ship them with your container log
driver or log collector.

## Connections to Wazuh

### TLS verification

| Setting | Default | Effect |
|---|---|---|
| `WAZUH_VERIFY_SSL` | `true` | Verify the Manager API certificate. |
| `WAZUH_ALLOW_SELF_SIGNED` | `false` | `true` disables Manager certificate verification. |
| `WAZUH_CA_BUNDLE` | *(none)* | CA PEM trusted for the Manager and Indexer instead of the system store. |
| `WAZUH_INDEXER_VERIFY_SSL` | `true` | Verify the Indexer certificate. Not affected by `WAZUH_ALLOW_SELF_SIGNED`. |

Manager verification is on by default. The stock Wazuh API certificate is self-signed for
`CN=wazuh.com` without a subjectAltName and cannot be verified for any host; reissue it with a
subjectAltName matching `WAZUH_HOST` and set `WAZUH_CA_BUNDLE`, or opt out with
`WAZUH_ALLOW_SELF_SIGNED=true` (logged at startup; as an error in production). See
[Manager TLS](../configuration.md#manager-tls). Clusters in `clusters.json` accept a per-cluster `ca_bundle`.

### Least-privilege Wazuh accounts

Create a dedicated Manager API user rather than using the built-in admin account. The Manager
API actions the server uses (from the `x-rbac-actions` of each endpoint in the Wazuh 4.14 API
specification):

| Purpose | Actions | Resource type |
|---|---|---|
| Read tools | `agent:read`, `sca:read`, `syscheck:read`, `syscollector:read` | `agent:id` |
| | `cluster:read` | `node:id` |
| | `manager:read` | `*:*` |
| | `rules:read` | `rule:file` |
| | `group:read` (agent configuration lookup) | `group:id` |
| Write tools (only if you grant `wazuh:write`) | `active-response:command`, `agent:restart` | `agent:id` |
| | `manager:restart` (used by `wazuh_restart` on agent `000`) | `*:*` |

Create the user with `POST /security/users`, a policy per resource type with
`POST /security/policies`, a role with `POST /security/roles`, then link them with
`POST /security/roles/{role_id}/policies` and `POST /security/users/{user_id}/roles`. See the
[Wazuh RBAC documentation](https://documentation.wazuh.com/current/user-manual/api/rbac/index.html).
If you never grant `wazuh:write`, leave out the write actions so a compromised server cannot
run active response.

The Indexer account needs search access to `wazuh-alerts-*` and
`wazuh-states-vulnerabilities-*` (prefixed with the remote cluster name when `ccs_prefix` is
used). It does not need write access.

## Container and deployment hardening

`Dockerfile`:

- Multi-stage build on `python:<version>-alpine`; build tools stay in the builder stage.
- `pip` is uninstalled from the runtime image.
- Runs as UID/GID 1000 (`USER 1000:1000`) with `tini` as the entrypoint.

`compose.yml`:

- Publishes the port on `127.0.0.1` only (`MCP_BIND` overrides it).
- `read_only: true`, `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]`.
- `tmpfs` for `/tmp` and `/app/logs` (`noexec,nosuid`); `./config` mounted read-only.
- CPU and memory limits (1 CPU, 512 MB).
- Sets `ENVIRONMENT=production`, so `AUTH_SECRET_KEY` is required unless `AUTH_MODE=none`.

Put a TLS-terminating reverse proxy in front and add it to `TRUSTED_PROXIES` if it is not on
loopback. A minimal nginx TLS block:

```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_buffering off;   # needed for the SSE stream on GET /mcp
```

## CI security checks

`.github/workflows/security.yml` runs on pushes to `main` that touch Python, dependency or
Dockerfile files, weekly, and on demand:

| Check | Blocking |
|---|---|
| `pip-audit` on installed dependencies | Yes |
| Bandit on `src/` | Yes |
| Semgrep (`--config auto`), SARIF uploaded to the Security tab | No (advisory) |
| Trivy filesystem scan, fixable HIGH/CRITICAL | Yes |
| hadolint on the Dockerfile | Yes |
| TruffleHog (verified secrets, push and pull request events) | Yes |
| Gitleaks (pinned version, checksum-verified download) | Yes |

`.github/workflows/docker-publish.yml` builds the image, scans it with Trivy (fixable
HIGH/CRITICAL fail the job) and only then pushes the multi-arch image to GHCR.

## Known limitations

- **Stock Manager certificates need action.** Verification is on by default, and the stock
  self-signed certificate has no subjectAltName; deployments must reissue it or explicitly
  opt out with `WAZUH_ALLOW_SELF_SIGNED=true`, which sends the API credentials unverified.
- **Per-process security state.** OAuth clients, authorization codes, refresh-token records, the
  revocation denylist and rate-limit counters live in process memory. They are not shared
  between replicas and are lost on restart (for example, a revoked OAuth token becomes usable
  again on another replica until it expires). `REDIS_URL` moves MCP sessions to Redis, not this
  state. Run a single instance, or use sticky routing and short token lifetimes.
- **No inbound TLS.** HTTPS depends on the reverse proxy.
- **Shared Wazuh identity.** All MCP users act through the same Wazuh account; Wazuh's own audit
  trail cannot tell them apart. Use the server's audit log for attribution.

## Production checklist

- [ ] `ENVIRONMENT=production` and `AUTH_MODE=bearer` or `oauth`.
- [ ] `AUTH_SECRET_KEY` is random, at least 32 characters, and identical on all replicas.
- [ ] One API key per user (`API_KEYS`), with `wazuh:write` only where needed.
- [ ] `ALLOWED_ORIGINS` lists only the origins your clients use.
- [ ] TLS terminated at a reverse proxy; the server port not exposed directly; the proxy in
      `TRUSTED_PROXIES` if it is not on loopback.
- [ ] Manager certificate verified (`WAZUH_ALLOW_SELF_SIGNED` left `false`), using a reissued certificate and `WAZUH_CA_BUNDLE` where needed;
      `WAZUH_INDEXER_VERIFY_SSL=true`.
- [ ] Dedicated least-privilege Wazuh API and Indexer accounts.
- [ ] `WAZUH_REQUIRE_ACTION_CONFIRMATION=true` and `WAZUH_PROTECTED_IPS` set if write tools are
      enabled; otherwise remove them with `WAZUH_TOOLSETS`/`WAZUH_DISABLED_TOOLS`.
- [ ] `OAUTH_ISSUER_URL` set and `OAUTH_ENABLE_DCR=false` unless registration is needed.
- [ ] `wazuh_mcp_server.audit` records collected and retained.
- [ ] `.env` permissions restricted to the service account.

See also: [Configuration](../configuration.md), [Operations](../OPERATIONS.md),
[Troubleshooting](../TROUBLESHOOTING.md).
